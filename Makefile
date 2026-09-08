test-current:
	docker build --no-cache --pull --progress=plain --tag python-base-current -f Dockerfile.current .
	trivy image --severity HIGH,CRITICAL,MEDIUM python-base-current
build-python:
	docker build --no-cache --pull --progress=plain --tag python-base-local -f Dockerfile.python-base .
build-python-fast:
	docker build --pull --progress=plain --tag python-base -f Dockerfile.python-base .
build-nodejs:
	docker build --no-cache --pull --progress=plain --tag nodejs-base-local -f Dockerfile.nodejs-base .
build-java:
	docker build --no-cache --pull --progress=plain --tag openjdk17-base-local -f openjdk17.nodejs-base .
run-docker:
	docker run -it --rm cdsp/python-base:latest
# run Docker image and print out PYTHON_ENV environment variable
run-docker-env: build-python-fast
	docker run --rm python-base:latest cat /tmp/versions.txt > versions.txt
run-local-action-tag:
	act push -e tag.json -W ./.github/workflows/publish-base-images.yml
run-local-action-push:
	act push -e main.json -W ./.github/workflows/create-release-tag.yml
trivy-python:
	docker build --pull --progress=plain --tag python-base -f Dockerfile.python-base .
	trivy image --severity HIGH,CRITICAL,MEDIUM python-base
# Lint GitHub Actions workflows.
# actionlint (through at least v1.7.12) does not yet understand GitHub's
# self-repository "$/..." action syntax and misreports it as an invalid action
# format. The -ignore pattern suppresses only that false positive; zizmor lints
# the same files in CI and accepts $/.
# SHELLCHECK_OPTS=--severity=warning drops the pre-existing SC2086/SC2129/etc
# info/style noise (tracked as tech debt) while still catching warning+ issues.
lint:
	SHELLCHECK_OPTS='--severity=warning' actionlint -ignore 'specifying action "\$$/.+" in invalid format' .github/workflows/*.yml
# Preview the workflow security findings CI reports to code-scanning
# (zizmorcore/zizmor-action, regular persona). Advisory only: the CI job uploads
# results and does not fail on them. --offline skips online-only audits (CI runs
# those too); drop it and export GH_TOKEN to match CI exactly.
zizmor:
	zizmor --offline .github/workflows/*.yml
