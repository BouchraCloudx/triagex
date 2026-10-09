pipeline {
    agent any

    options {
        timestamps()
        ansiColor('xterm')
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }

    environment {
        APP_DIR       = 'demo-app'
        IMAGE         = "triagex-demo:${env.BUILD_NUMBER}"
        TRIVY_CACHE   = '/var/lib/jenkins/.cache/trivy'
        AI_ENGINE_URL = 'http://192.168.138.11:8000'
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

        stage('Triage IA et quality gate') {
            steps {
                sh '''
                    set +x
                    rc=0
                    python3 scripts/triage_client.py \
                      --url "$AI_ENGINE_URL" \
                      --reports-dir reports \
                      --source-dir "$APP_DIR" \
                      --out-dir reports || rc=$?

                    # Examen de l'IA : comparaison à la correction, sans influencer le quality gate
                    python3 scripts/evaluate_ai.py \
                      --triage reports/triage.json \
                      --truth evaluation/ground_truth.json \
                      --source "$APP_DIR/app.py" \
                      --out reports/ai-evaluation.json || true

                    exit $rc
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/*', allowEmptyArchive: true
            publishHTML(target: [
                reportDir: 'reports',
                reportFiles: 'triage.html',
                reportName: 'Rapport TriageX',
                keepAll: true,
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])
            sh 'docker rmi "$IMAGE" || true'
        }
    }
}
