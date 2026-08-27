package repository

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// s3ClientParams 描述构造 S3 兼容客户端所需的参数。
type s3ClientParams struct {
	Endpoint        string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	ForcePathStyle  bool
	// ProxyURL 可选出站代理（http/https/socks5/socks5h）。空 = 直连。
	// 调用方需保证已通过 proxyurl 校验；这里只做 URL 解析，失败即报错不回退直连。
	ProxyURL string
}

// newS3Client 构造一个 S3 兼容客户端，兼容 AWS S3 / Cloudflare R2 / 阿里云 OSS / MinIO。
//
// 通过 SwapComputePayloadSHA256ForUnsignedPayloadMiddleware + RequestChecksumCalculationWhenRequired
// 规避阿里云 OSS 不兼容 s3manager 分片签名的问题（backup 与 image storage 共用此构造）。
func newS3Client(ctx context.Context, p s3ClientParams) (*s3.Client, error) {
	region := p.Region
	if region == "" {
		region = "auto" // Cloudflare R2 默认 region
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(p.AccessKeyID, p.SecretAccessKey, ""),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	httpClient, err := s3HTTPClient(p.ProxyURL)
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if p.Endpoint != "" {
			o.BaseEndpoint = &p.Endpoint
		}
		if p.ForcePathStyle {
			o.UsePathStyle = true
		}
		if httpClient != nil {
			o.HTTPClient = httpClient
		}
		o.APIOptions = append(o.APIOptions, v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware)
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	}), nil
}

// s3HTTPClient 返回带代理的 SDK HTTP 客户端。proxyURL 为空时返回 (nil, nil)，走 SDK 默认直连。
//
// 仅覆写 Transport.Proxy 一个字段：NewBuildableClient 的其余默认值（TLS 握手超时、
// 连接池、重试行为）全部保留。https 请求经 http(s) 代理自动走 CONNECT 隧道，
// 经 socks5 代理由 net/http 原生隧道并远端解析域名（socks5h 语义），R2/OSS 均适用。
func s3HTTPClient(proxyURL string) (*awshttp.BuildableClient, error) {
	proxyFn, err := s3ProxyFunc(proxyURL)
	if err != nil {
		return nil, err
	}
	if proxyFn == nil {
		return nil, nil
	}
	client := awshttp.NewBuildableClient()
	client = client.WithTransportOptions(func(t *http.Transport) {
		t.Proxy = proxyFn
	})
	return client, nil
}

// s3ProxyFunc 解析代理 URL 为 http.Transport.Proxy 函数。空代理返回 (nil, nil) 表示直连。
func s3ProxyFunc(proxyURL string) (func(*http.Request) (*url.URL, error), error) {
	trimmed := strings.TrimSpace(proxyURL)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		return nil, fmt.Errorf("parse s3 proxy url %q: invalid proxy url", proxyURL)
	}
	return http.ProxyURL(parsed), nil
}
