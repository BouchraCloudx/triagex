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
        APP_URL       = 'http://192.168.138.11:3000'
    }

    stages {
        stage('Préparation') {
            steps {
                sh '''
                    rm -rf reports build && mkdir -p reports build
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

        // Atteint uniquement si le quality gate est validé : l'étape précédente échoue sinon.
        stage('Déploiement (Ansible)') {
            environment {
                ANSIBLE_NOCOLOR = '1'
            }
            steps {
                sh '''
                    set +x
                    # On déploie exactement l'image analysée par Trivy, sans la reconstruire
                    docker save -o build/app-image.tar "$IMAGE"
                    echo "Image analysée exportée : $IMAGE ($(du -h build/app-image.tar | cut -f1))"

                    publish() {
                        printf '{"build": "%s", "image": "%s", "success": %s}' "$BUILD_NUMBER" "$IMAGE" "$1" \
                          > reports/deployment.json
                        curl -fsS -m 10 -X POST -H "Content-Type: application/json" \
                          --data @reports/deployment.json "$AI_ENGINE_URL/deployment" > /dev/null \
                          || echo "Métriques de déploiement non publiées (moteur IA injoignable)"
                    }

                    cd ansible
                    if ansible-playbook -i inventory-jenkins.ini deploy-app.yml \
                         -e "app_image=$IMAGE" \
                         -e "app_archive=$WORKSPACE/build/app-image.tar" \
                         -e "app_build=$BUILD_NUMBER"; then
                        cd ..
                        publish true
                        echo "Vérification depuis le serveur CI : $(curl -fsS -m 10 "$APP_URL/")"
                        echo "DÉPLOYÉ : $IMAGE est en production sur $APP_URL"
                    else
                        cd ..
                        publish false
                        echo "ÉCHEC DU DÉPLOIEMENT : voir les messages Ansible ci-dessus."
                        exit 1
                    fi
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
            sh 'rm -rf build; docker rmi "$IMAGE" || true'
        }
        success {
            script {
                currentBuild.description = "Déployé : ${env.IMAGE}"
            }
        }
        failure {
            script {
                currentBuild.description = 'Non déployé'
            }
        }
    }
}
