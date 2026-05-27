use anyhow::Result;
use aws_config::{BehaviorVersion, Region};
use aws_smithy_http_client::{tls, Builder as HttpClientBuilder};

#[derive(Clone)]
pub struct ClientFactory {
    pub config: aws_config::SdkConfig,
    pub profile: String,
    pub regions: Vec<String>,
}

impl ClientFactory {
    pub async fn new(profile: Option<&str>, regions: Option<&str>) -> Result<Self> {
        let profile = profile.unwrap_or("default").to_string();

        // Build a ring-based TLS HTTP client to avoid aws-lc-sys (requires C toolchain).
        let http_client = HttpClientBuilder::new()
            .tls_provider(tls::Provider::Rustls(
                tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();

        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .profile_name(&profile)
            .http_client(http_client);

        // If a specific region was requested (or the first in a list), seed the SDK config
        // with it so credential loading (IMDS, SSO) uses the right region.
        if let Some(first) = regions.and_then(|s| s.split(',').next()) {
            loader = loader.region(Region::new(first.trim().to_string()));
        }

        let config = loader.load().await;

        let regions = match regions {
            Some(r) => r.split(',').map(|s| s.trim().to_string()).collect(),
            None => vec!["us-east-1".to_string()],
        };

        Ok(Self { config, profile, regions })
    }

    pub fn sts(&self) -> aws_sdk_sts::Client {
        aws_sdk_sts::Client::new(&self.config)
    }

    pub fn ec2(&self, region: &str) -> aws_sdk_ec2::Client {
        let conf = aws_sdk_ec2::config::Builder::from(&self.config)
            .region(aws_sdk_ec2::config::Region::new(region.to_string()))
            .build();
        aws_sdk_ec2::Client::from_conf(conf)
    }

    pub fn s3(&self) -> aws_sdk_s3::Client {
        aws_sdk_s3::Client::new(&self.config)
    }

    pub fn iam(&self) -> aws_sdk_iam::Client {
        aws_sdk_iam::Client::new(&self.config)
    }

    pub fn lambda(&self, region: &str) -> aws_sdk_lambda::Client {
        let conf = aws_sdk_lambda::config::Builder::from(&self.config)
            .region(aws_sdk_lambda::config::Region::new(region.to_string()))
            .build();
        aws_sdk_lambda::Client::from_conf(conf)
    }

    pub fn rds(&self, region: &str) -> aws_sdk_rds::Client {
        let conf = aws_sdk_rds::config::Builder::from(&self.config)
            .region(aws_sdk_rds::config::Region::new(region.to_string()))
            .build();
        aws_sdk_rds::Client::from_conf(conf)
    }

    pub fn secretsmanager(&self, region: &str) -> aws_sdk_secretsmanager::Client {
        let conf = aws_sdk_secretsmanager::config::Builder::from(&self.config)
            .region(aws_sdk_secretsmanager::config::Region::new(region.to_string()))
            .build();
        aws_sdk_secretsmanager::Client::from_conf(conf)
    }

    pub fn ecs(&self, region: &str) -> aws_sdk_ecs::Client {
        let conf = aws_sdk_ecs::config::Builder::from(&self.config)
            .region(aws_sdk_ecs::config::Region::new(region.to_string()))
            .build();
        aws_sdk_ecs::Client::from_conf(conf)
    }

    pub fn ssm(&self, region: &str) -> aws_sdk_ssm::Client {
        let conf = aws_sdk_ssm::config::Builder::from(&self.config)
            .region(aws_sdk_ssm::config::Region::new(region.to_string()))
            .build();
        aws_sdk_ssm::Client::from_conf(conf)
    }

    pub fn dynamodb(&self, region: &str) -> aws_sdk_dynamodb::Client {
        let conf = aws_sdk_dynamodb::config::Builder::from(&self.config)
            .region(aws_sdk_dynamodb::config::Region::new(region.to_string()))
            .build();
        aws_sdk_dynamodb::Client::from_conf(conf)
    }

    pub fn cloudformation(&self, region: &str) -> aws_sdk_cloudformation::Client {
        let conf = aws_sdk_cloudformation::config::Builder::from(&self.config)
            .region(aws_sdk_cloudformation::config::Region::new(region.to_string()))
            .build();
        aws_sdk_cloudformation::Client::from_conf(conf)
    }

    pub fn route53(&self) -> aws_sdk_route53::Client {
        aws_sdk_route53::Client::new(&self.config)
    }

    pub fn eks(&self, region: &str) -> aws_sdk_eks::Client {
        let conf = aws_sdk_eks::config::Builder::from(&self.config)
            .region(aws_sdk_eks::config::Region::new(region.to_string()))
            .build();
        aws_sdk_eks::Client::from_conf(conf)
    }

    pub fn ecr(&self, region: &str) -> aws_sdk_ecr::Client {
        let conf = aws_sdk_ecr::config::Builder::from(&self.config)
            .region(aws_sdk_ecr::config::Region::new(region.to_string()))
            .build();
        aws_sdk_ecr::Client::from_conf(conf)
    }

    pub fn sns(&self, region: &str) -> aws_sdk_sns::Client {
        let conf = aws_sdk_sns::config::Builder::from(&self.config)
            .region(aws_sdk_sns::config::Region::new(region.to_string()))
            .build();
        aws_sdk_sns::Client::from_conf(conf)
    }

    pub fn sqs(&self, region: &str) -> aws_sdk_sqs::Client {
        let conf = aws_sdk_sqs::config::Builder::from(&self.config)
            .region(aws_sdk_sqs::config::Region::new(region.to_string()))
            .build();
        aws_sdk_sqs::Client::from_conf(conf)
    }

    pub fn codebuild(&self, region: &str) -> aws_sdk_codebuild::Client {
        let conf = aws_sdk_codebuild::config::Builder::from(&self.config)
            .region(aws_sdk_codebuild::config::Region::new(region.to_string()))
            .build();
        aws_sdk_codebuild::Client::from_conf(conf)
    }
}
