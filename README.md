This repository contains Dockerfile to build security scanning image and
secscan.py wrapper tool.

## Example usage

To use with Gitlab CI, you need to define following variables:

- RELEASE_IMAGE_NAME (name of docker image)
- REPORTS_SQS_URL (URL for Amazon SQS queue)
- REPORTS_SQS_ACCESS_KEY and REPORTS_SQS_SECRET_KEY

Alternatively you can send reports directly into Elasticsearch. For more info,
see `secscan.py --help`.

```yaml
test-trivy:
  <<: *release
  stage: publish-test
  image: secscan
  script:
    - podman pull docker://${RELEASE_IMAGE_NAME}:${CI_COMMIT_SHA}
    - podman push docker://${RELEASE_IMAGE_NAME}:${CI_COMMIT_SHA} oci:`pwd`/ociimage
    - trivy-report --scan-tag trivy.scan.${CI_PROJECT_NAME} --vuln-tag trivy.vuln.${CI_PROJECT_NAME} --sqs-url ${REPORTS_SQS_URL} --sqs-access-key ${REPORTS_SQS_ACCESS_KEY} --sqs-secret-key ${REPORTS_SQS_SECRET_KEY} --image `pwd`/ociimage

test-depcheck:
  <<: *release
  stage: publish-test
  image: secscan
  before_script: []
  after_script: []
  script:
    - depcheck-report --scan-tag depcheck.scan.${CI_PROJECT_NAME} --vuln-tag depcheck.vuln.${CI_PROJECT_NAME} --sqs-url ${REPORTS_SQS_URL} --sqs-access-key ${REPORTS_SQS_ACCESS_KEY} --sqs-secret-key ${REPORTS_SQS_SECRET_KEY} --image `pwd`/ociimage
  artifacts:
    when: always
    paths: [dependency-check-report.html]
    reports:
      junit: dependency-check-junit.xml

```
