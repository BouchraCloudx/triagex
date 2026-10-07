pipeline {
    agent any

    options {
        timestamps()
        ansiColor('xterm')
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }

    environment {
        APP_DIR     = 'demo-app'
        IMAGE       = "triagex-demo:${env.BUILD_NUMBER}"
        TRIVY_CACHE = '/var/lib/jenkins/.cache/trivy'
    }

    stages {
        stage('Préparation') {
            steps {
                sh '''
                    rm -rf reports && mkdir -p reports
                    echo "Utilisateur : $(id -un) - Image : $IMAGE"
                '''
            }
        }

        stage('Secrets (Gitleaks)') {
            steps {
                sh '''
                    docker run --rm -u "$(id -u):$(id -g)" \
                      -v "$WORKSPACE:/repo" zricethezav/gitleaks:latest \
                      dir /repo/$APP_DIR --no-banner \
                      --report-format json --report-path /repo/reports/gitleaks.json \
                      --exit-code 0
                '''
            }
        }

        stage('SAST (Semgrep)') {
            steps {
                sh '''
                    docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
                      -v "$WORKSPACE:/src" semgrep/semgrep:latest \
                      semgrep scan --config p/python --metrics=off \
                      --json --output /src/reports/semgrep.json /src/$APP_DIR
                '''
            }
        }

        stage('Dépendances (Trivy)') {
            steps {
                sh '''
                    docker run --rm -u "$(id -u):$(id -g)" \
                      -v "$WORKSPACE:/src" -v "$TRIVY_CACHE:/cache" aquasec/trivy:latest \
                      fs --cache-dir /cache --scanners vuln --quiet \
                      --format json --output /src/reports/trivy-fs.json /src/$APP_DIR
                '''
            }
        }

        stage('IaC (Checkov)') {
            steps {
                sh '''
                    docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
                      -v "$WORKSPACE:/src" bridgecrew/checkov:latest \
                      -d /src/$APP_DIR --framework dockerfile \
                      --output json --soft-fail --quiet > reports/checkov.json
                '''
            }
        }

        stage('Build image') {
            steps {
                sh 'docker build -t "$IMAGE" "$APP_DIR"'
            }
        }

        stage('Scan image (Trivy)') {
            steps {
                sh '''
                    docker run --rm -u "$(id -u):$(id -g)" \
                      --group-add "$(stat -c %g /var/run/docker.sock)" \
                      -v /var/run/docker.sock:/var/run/docker.sock \
                      -v "$WORKSPACE:/src" -v "$TRIVY_CACHE:/cache" aquasec/trivy:latest \
                      image --cache-dir /cache --scanners vuln --quiet \
                      --format json --output /src/reports/trivy-image.json "$IMAGE"
                '''
            }
        }

        stage('Résumé et quality gate') {
            steps {
                sh '''
                    count() { jq "$2" "reports/$1" 2>/dev/null || echo 0; }

                    SECRETS=$(count gitleaks.json 'length')
                    SAST=$(count semgrep.json '.results | length')
                    SCA=$(count trivy-fs.json '[.Results[]?.Vulnerabilities[]?] | length')
                    IAC=$(count checkov.json 'if type=="array" then map(.results.failed_checks | length) | add else .results.failed_checks | length end')
                    IMG=$(count trivy-image.json '[.Results[]?.Vulnerabilities[]?] | length')
                    TOTAL=$((SECRETS + SAST + SCA + IAC + IMG))

                    echo "======================================"
                    echo " RÉSUMÉ DES ALERTES BRUTES (avant IA)"
                    echo "======================================"
                    echo " Secrets (Gitleaks)      : $SECRETS"
                    echo " Code (Semgrep)          : $SAST"
                    echo " Dépendances (Trivy)     : $SCA"
                    echo " Dockerfile (Checkov)    : $IAC"
                    echo " Image Docker (Trivy)    : $IMG"
                    echo "--------------------------------------"
                    echo " TOTAL                   : $TOTAL"
                    echo "======================================"

                    printf '{"secrets": %s, "sast": %s, "sca": %s, "iac": %s, "image": %s, "total": %s}\n' \
                      "$SECRETS" "$SAST" "$SCA" "$IAC" "$IMG" "$TOTAL" > reports/summary.json

                    if [ "$SECRETS" -gt 0 ]; then
                        echo "QUALITY GATE : ÉCHEC - $SECRETS secret(s) détecté(s) dans le code."
                        exit 1
                    fi
                    echo "QUALITY GATE : OK"
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/*.json', allowEmptyArchive: true
            sh 'docker rmi "$IMAGE" || true'
        }
    }
}
