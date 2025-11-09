# CDN Deployment Guide

This guide provides instructions for configuring a Content Delivery Network (CDN) to work with the CBC Auth Service, specifically for distributing the JSON Web Key Set (JWKS).

## AWS CloudFront (Example)

This example demonstrates how to configure AWS CloudFront as the CDN for the CBC Auth Service.

### 1. Create a CloudFront Distribution

1.  **Origin Domain:** The origin domain should point to the load balancer of the CBC Auth Service.
2.  **Protocol:** Use **HTTPS only** for secure communication between CloudFront and the origin.
3.  **Origin Path:** Leave this blank unless the service is hosted under a specific path.

### 2. Configure Cache Behavior

Create a new cache behavior or edit the default one to match the JWKS endpoint:

*   **Path Pattern:** `/api/v1/auth/jwks/*`
*   **Viewer Protocol Policy:** Redirect HTTP to HTTPS
*   **Allowed HTTP Methods:** GET, HEAD
*   **Cached HTTP Methods:** GET, HEAD (ensure this is selected)
*   **Cache Policy:** Create a new cache policy with the following settings:
    *   **Default TTL:** 3600 seconds (1 hour)
    *   **Min TTL:** 0 seconds
    *   **Max TTL:** 86400 seconds (24 hours)
    *   **Cache Key Settings:**
        *   **Headers:** `ETag` (or `If-None-Match`)
        *   **Cookies:** None
        *   **Query Strings:** None
*   **Origin Shield:** Enable Origin Shield for better performance and origin protection.
*   **Compress:** Yes

### 3. Configure IAM Permissions for Cache Invalidation

The CBC Auth Service needs permission to create cache invalidations in CloudFront. Create an IAM policy with the following permissions and attach it to the IAM role or user that the service uses:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "cloudfront:CreateInvalidation",
            "Resource": "arn:aws:cloudfront::<your-aws-account-id>:distribution/<your-distribution-id>"
        }
    ]
}
```

Replace `<your-aws-account-id>` and `<your-distribution-id>` with your actual AWS account ID and CloudFront distribution ID.

### 4. Configure the CBC Auth Service

Update the configuration of the CBC Auth Service to enable the CloudFront adapter:

```yaml
cdn:
  purge_enabled: true
  provider: "aws_cloudfront"
  distribution_id: "<your-distribution-id>"
```

Ensure that the service has the necessary AWS credentials configured, either through environment variables, an IAM role for EC2, or an IAM role for service accounts (IRSA) in EKS.
