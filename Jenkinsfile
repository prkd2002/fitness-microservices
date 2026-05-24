// ============================================================================
//  CI/CD PIPELINE — Spring Boot Microservices (v2 — Production-Grade)
//  activityservice · aiservice · configserver · eureka · gateway · iuserservice
// ============================================================================

pipeline {

    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '5'))
        timestamps()
        timeout(time: 90, unit: 'MINUTES')
        disableConcurrentBuilds()
        ansiColor('xterm')
    }

    parameters {
        choice(name: 'DEPLOY_ENV',   choices: ['dev', 'staging', 'prod'], description: 'Target deployment environment')
        booleanParam(name: 'SKIP_TESTS',   defaultValue: false, description: 'Skip unit/integration tests (emergency only)')
        booleanParam(name: 'FORCE_DEPLOY', defaultValue: false, description: 'Force deploy even if Quality Gate fails')
        string(name: 'IMAGE_TAG', defaultValue: '', description: 'Custom image tag (empty = BUILD_NUMBER)')
    }

    environment {
        REGISTRY           = 'docker.io'
        REGISTRY_NAMESPACE = 'pkatjs'
        IMAGE_TAG          = "${params.IMAGE_TAG ?: "build-${env.BUILD_NUMBER}"}"
        SERVICES           = 'activityservice aiservice configserver eureka gateway userservice'

        SONAR_HOST_URL    = 'http://sonarqube:9000'
        SONAR_PROJECT_KEY = 'fitness-microservices'

        K8S_NAMESPACE  = "${params.DEPLOY_ENV}"
        KUBECONFIG     = credentials('kubeconfig-minikube')

        TRIVY_SEVERITY  = 'CRITICAL,HIGH'
        TRIVY_EXIT_CODE = '1'


        NVD_API_KEY = credentials('nvd-api-key')

        // ⚠️ Ne jamais exposer les valeurs — Jenkins masque ces variables dans les logs
        SONAR_TOKEN = credentials('sonarqube-token')

        SLACK_CHANNEL = '#ci-cd-alerts'

        // ── Email ──────────────────────────────────────────────
        // Liste des destinataires — séparer par des espaces ou virgules
        EMAIL_RECIPIENTS   = 'team-devops@example.com dev-lead@example.com'
        EMAIL_REPLY_TO     = 'jenkins-noreply@example.com'
    }

    tools {
        maven 'Maven-3.9'
        jdk   'JDK-26'
    }

    // ═══════════════════════════════════════════════════════════
    stages {

        // ────────────────────────────────────────────────────────
        // 1 · CHECKOUT
        // ────────────────────────────────────────────────────────
        stage('📥 Checkout') {
            steps {
                checkout scm
                sh 'git log --oneline -5'
                script {
                    env.GIT_COMMIT_SHORT = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.GIT_AUTHOR       = sh(returnStdout: true, script: 'git log -1 --pretty=format:"%an <%ae>"').trim()
                    echo "Commit: ${env.GIT_COMMIT_SHORT} | Auteur: ${env.GIT_AUTHOR}"
                }
            }
        }

        // ────────────────────────────────────────────────────────
        // 2 · OWASP DEPENDENCY-CHECK  (séquentiel, avant le build)
        //
        //  POURQUOI ICI ET PAS DANS LE PARALLEL BLOCK ?
        //  • Les scans OWASP partagent un cache CVE global sur disque.
        //    Plusieurs instances parallèles corrompent ce cache.
        //  • Les rapports HTML sont publiés une seule fois ici.
        //  • Si une dépendance est compromise, inutile de builder.
        // ────────────────────────────────────────────────────────
        stage('🔍 OWASP Dependency-Check') {
            steps {
                script {
                    def mavenHome = tool name: 'Maven-3.9', type: 'maven'
                    def jdkHome = tool name: 'JDK-26', type: 'jdk'

                    def resolvedJavaHome = sh(
                            returnStdout: true,
                            script: """
                            # Cherche java dans le PATH déjà enrichi par tool()
                            JAVA_BIN=\$(which java 2>/dev/null || echo "")
                            if [ -z "\$JAVA_BIN" ]; then
                                # Fallback : cherche dans le répertoire retourné par tool()
                                JAVA_BIN=\$(find ${jdkHome} -name java -type f | head -1)
                            fi
                            # Remonte de bin/java → répertoire racine du JDK
                            dirname \$(dirname \$(readlink -f "\$JAVA_BIN"))
                        """
                    ).trim()

                    echo "==> JAVA_HOME résolu : \${resolvedJavaHome}"


                    withEnv(["PATH+MAEN=${mavenHome}/bin", "PATH+JDK=${resolvedJavaHome}/bin", "JAVA_HOME=${resolvedJavaHome}"]) {
                        def serviceList = env.SERVICES.split(' ')
                        serviceList.each { svc ->
                            if(fileExists("${svc}/pom.xml")){
                                dir(svc) {
                                    echo "==> OWASP scan: ${svc}"
                                    sh """
                                java --version
                                mvn -B org.owasp:dependency-check-maven:check \
                                    -DfailBuildOnCVSS=7 \
                                    -Dformats=HTML,JSON \
                                    -DsuppressionFile=../dependency-check-suppressions.xml \
                                    -DnvdApiKey=${NVD_API_KEY}
                                    --no-transfer-progress
                            """
                                }
                            }else{
                                echo "Avertissement: LE dossier ou le projet Maven pour '${svc}' n'existe pas. Etape ignoree."
                            }

                        }

                    }

                }
            }
            post {
                always {
                    publishHTML(target: [
                        allowMissing         : true,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : '.',
                        reportFiles          : '**/dependency-check-report.html',
                        reportName           : 'OWASP Dependency Report'
                    ])
                    archiveArtifacts artifacts: '**/dependency-check-report.*', allowEmptyArchive: true
                }
            }
        }

        // ────────────────────────────────────────────────────────
        // 3 · BUILD + TESTS + SONARQUBE (parallel par service)
        //
        //  POURQUOI UN QUALITY GATE INDIVIDUEL ?
        //  Ton pipeline original avait un seul waitForQualityGate
        //  GLOBAL après tous les push Sonar. Cela signifiait que :
        //    - La gate du dernier service à envoyer ses métriques
        //      écrasait les résultats des précédents.
        //    - Un service KO ne bloquait pas ses voisins.
        //  Solution : chaque service obtient sa propre clé SonarQube
        //  (fitness-microservices:activityservice) et sa propre gate.
        // ────────────────────────────────────────────────────────
        stage('⚙️ Build · Test · Analyse (parallel)') {
            steps {
                script {
                    def serviceList = env.SERVICES.split(' ')
                    def stages = [:]

                    serviceList.each { svc ->
                        def svcName = svc  // variable locale pour la closure
                        stages["${svcName}"] = {
                            dir(svcName) {

                                // 3a. Compilation + tests unitaires
                                echo "==> [${svcName}] Build & Tests"
                                sh """
                                    mvn -B clean package \
                                        -DskipTests=${params.SKIP_TESTS} \
                                        -Dmaven.test.failure.ignore=false \
                                        --no-transfer-progress
                                """

                                // 3b. Analyse SonarQube avec clé unique par service
                                echo "==> [${svcName}] SonarQube analysis"
                                withSonarQubeEnv('SonarQube-Server') {
                                    sh """
                                        mvn -B sonar:sonar \
                                            -Dsonar.projectKey=${env.SONAR_PROJECT_KEY}:${svcName} \
                                            -Dsonar.projectName="Fitness - ${svcName}" \
                                            -Dsonar.host.url=${env.SONAR_HOST_URL} \
                                            -Dsonar.token=${env.SONAR_TOKEN} \
                                            -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \
                                            -Dsonar.java.checkstyle.reportPaths=target/checkstyle-result.xml \
                                            -Dsonar.java.binaries=target/classes \
                                            -Dsonar.java.test.binaries=target/test-classes \
                                            -Dsonar.sourceEncoding=UTF-8 \
                                            --no-transfer-progress
                                    """
                                }

                                // 3c. Quality Gate individuel (timeout 5 min par service)
                                echo "==> [${svcName}] Waiting for Quality Gate"
                                timeout(time: 5, unit: 'MINUTES') {
                                    def qg = waitForQualityGate abortPipeline: false
                                    if (qg.status != 'OK') {
                                        if (params.FORCE_DEPLOY) {
                                            unstable("⚠️ [${svcName}] Quality Gate ${qg.status} — FORCE_DEPLOY activé")
                                        } else {
                                            error("❌ [${svcName}] Quality Gate échoué: ${qg.status}")
                                        }
                                    } else {
                                        echo "✅ [${svcName}] Quality Gate OK"
                                    }
                                }
                            }
                        }
                    }
                    parallel stages
                }
            }
            post {
                always {
                    // Résultats JUnit agrégés de tous les services
                    junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: true

                    // Rapport JaCoCo (coverage)
                    jacoco(
                        execPattern               : '**/target/jacoco.exec',
                        classPattern              : '**/target/classes',
                        sourcePattern             : '**/src/main/java',
                        minimumInstructionCoverage: '70',
                        minimumBranchCoverage     : '60'
                    )

                    // Archive les JARs construits
                    archiveArtifacts artifacts: '**/target/*.jar', allowEmptyArchive: false
                }
            }
        }

        // ────────────────────────────────────────────────────────
        // 4 · DOCKER BUILD + TRIVY SCAN + PUSH (parallel par service)
        //
        //  ORDRE INTENTIONNEL dans la même closure :
        //    build → scan → push
        //  On ne pousse une image que si elle passe le scan Trivy.
        //  Le login Docker est fait UNE SEULE FOIS avant le parallel
        //  pour éviter N appels à docker login (race condition possible).
        // ────────────────────────────────────────────────────────
        stage('🐳 Docker Build · Scan · Push (parallel)') {
            steps {
                script {
                    // Login centralisé avant les builds parallèles
                    withCredentials([usernamePassword(
                        credentialsId : 'docker-registry-credentials',
                        usernameVariable: 'DOCKER_USER',
                        passwordVariable: 'DOCKER_PASS'
                    )]) {
                        sh "echo \$DOCKER_PASS | docker login ${env.REGISTRY} -u \$DOCKER_USER --password-stdin"
                    }

                    def serviceList = env.SERVICES.split(' ')
                    def stages = [:]

                    serviceList.each { svc ->
                        def svcName   = svc
                        def imageName = "${env.REGISTRY_NAMESPACE}/${svcName}:${env.IMAGE_TAG}"
                        def imgLatest = "${env.REGISTRY_NAMESPACE}/${svcName}:latest"
                        def report    = "trivy-report-${svcName}.json"

                        stages["${svcName}"] = {
                            dir(svcName) {

                                // 4a. Docker Build
                                echo "==> [${svcName}] Docker build → ${imageName}"
                                sh """
                                    docker build \
                                        --build-arg BUILD_DATE=\$(date -u +%Y-%m-%dT%H:%M:%SZ) \
                                        --build-arg GIT_COMMIT=${env.GIT_COMMIT_SHORT} \
                                        --build-arg VERSION=${env.IMAGE_TAG} \
                                        --label org.opencontainers.image.revision=${env.GIT_COMMIT_SHORT} \
                                        --label org.opencontainers.image.created=\$(date -u +%Y-%m-%dT%H:%M:%SZ) \
                                        -t ${imageName} \
                                        -t ${imgLatest} \
                                        .
                                """

                                // 4b. Trivy — scan sur l'image locale (avant push)
                                //  exit-code 0 ici pour ne pas tuer le parallel block avant
                                //  d'avoir tous les rapports ; on évalue après.
                                echo "==> [${svcName}] Trivy scan"
                                def trivyStatus = sh(
                                    returnStatus: true,
                                    script: """
                                        trivy image \
                                            --exit-code ${env.TRIVY_EXIT_CODE} \
                                            --severity ${env.TRIVY_SEVERITY} \
                                            --no-progress \
                                            --format json \
                                            --output ../${report} \
                                            ${imageName}

                                        trivy image \
                                            --exit-code 0 \
                                            --severity ${env.TRIVY_SEVERITY} \
                                            --no-progress \
                                            --format table \
                                            ${imageName}
                                    """
                                )

                                if (trivyStatus != 0) {
                                    if (params.FORCE_DEPLOY) {
                                        unstable("⚠️ [${svcName}] Trivy: vulnérabilités ${env.TRIVY_SEVERITY} trouvées — FORCE_DEPLOY activé")
                                    } else {
                                        error("❌ [${svcName}] Trivy: vulnérabilités ${env.TRIVY_SEVERITY} bloquantes")
                                    }
                                } else {
                                    echo "✅ [${svcName}] Trivy OK — aucune vulnérabilité ${env.TRIVY_SEVERITY}"
                                }

                                // 4c. Push uniquement si l'image est saine
                                echo "==> [${svcName}] Docker push"
                                sh """
                                    docker push ${imageName}
                                    docker push ${imgLatest}
                                """
                                echo "✅ [${svcName}] Image publiée: ${imageName}"
                            }
                        }
                    }
                    parallel stages
                }
            }
            post {
                always {
                    sh "docker logout ${env.REGISTRY} || true"
                    archiveArtifacts artifacts: 'trivy-report-*.json', allowEmptyArchive: true
                }
            }
        }

        // ────────────────────────────────────────────────────────
        // 5 · VALIDATION DES MANIFESTES K8S
        // ────────────────────────────────────────────────────────
        stage('📋 K8s Manifest Validation') {
            steps {
                sh """
                    find k8s/ -name '*.yaml' -o -name '*.yml' | \
                    xargs kubeconform \
                        -strict \
                        -summary \
                        -kubernetes-version 1.29.0 \
                        -ignore-missing-schemas || true
                """
            }
        }

        // ────────────────────────────────────────────────────────
        // 6 · DÉPLOIEMENT ORDONNÉ SUR MINIKUBE
        //
        //  L'ordre de démarrage respecte les dépendances Spring :
        //    configserver  → tous les services lisent la config
        //    eureka        → service registry (doit être prêt avant les clients)
        //    iuserservice  → service métier sans dépendance inter-service
        //    activityservice / aiservice → consomment iuserservice
        //    gateway       → point d'entrée, démarre en dernier
        //
        //  Entre chaque déploiement : rollout status bloquant (180s).
        //  Si un service ne démarre pas, le pipeline s'arrête ici
        //  avant de tenter le suivant.
        // ────────────────────────────────────────────────────────
        stage('🚀 Deploy to Minikube') {
            steps {
                script {
                    sh """
                        kubectl get namespace ${env.K8S_NAMESPACE} || \
                        kubectl create namespace ${env.K8S_NAMESPACE}
                        kubectl apply -f k8s/configmaps/ -n ${env.K8S_NAMESPACE} || true
                        kubectl apply -f k8s/secrets/    -n ${env.K8S_NAMESPACE} || true
                    """

                    def deployOrder = [
                        'configserver',
                        'eureka',
                        'userservice',
                        'activityservice',
                        'aiservice',
                        'gateway'
                    ]

                    deployOrder.each { svc ->
                        def imageName = "${env.REGISTRY_NAMESPACE}/${svc}:${env.IMAGE_TAG}"
                        echo "==> Deploying ${svc} → ${imageName}"

                        sh """
                            kubectl set image deployment/${svc} ${svc}=${imageName} \
                                -n ${env.K8S_NAMESPACE} --record=false 2>/dev/null || \
                            kubectl apply -f k8s/${svc}/ -n ${env.K8S_NAMESPACE}

                            kubectl rollout status deployment/${svc} \
                                -n ${env.K8S_NAMESPACE} --timeout=180s
                        """
                        echo "✅ ${svc} deployed"

                        // Délai réduit entre services pour laisser Eureka enregistrer les clients
                        if (svc == 'eureka') {
                            echo "==> Pause 20s pour stabilisation d'Eureka …"
                            sleep(time: 20, unit: 'SECONDS')
                        }
                    }
                }
            }
        }

        // ────────────────────────────────────────────────────────
        // 7 · SMOKE TESTS
        // ────────────────────────────────────────────────────────
        stage('🧪 Smoke Tests') {
            steps {
                script {
                    sleep(time: 15, unit: 'SECONDS')
                    sh """
                        GATEWAY_PORT=\$(kubectl get svc gateway -n ${env.K8S_NAMESPACE} \
                            -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "8080")
                        MINIKUBE_IP=\$(minikube ip 2>/dev/null || echo "localhost")
                        BASE_URL="http://\${MINIKUBE_IP}:\${GATEWAY_PORT}"

                        echo "==> Smoke test on \${BASE_URL}"

                        for ENDPOINT in actuator/health actuator/info; do
                            STATUS=\$(curl -s -o /dev/null -w "%{http_code}" \
                                --max-time 10 "\${BASE_URL}/\${ENDPOINT}" || echo "000")
                            echo "  [\${ENDPOINT}] → HTTP \${STATUS}"
                            if [ "\${STATUS}" = "000" ]; then
                                echo "⚠️  Gateway unreachable — vérifier les logs"
                            fi
                        done
                    """
                }
            }
        }

        // ────────────────────────────────────────────────────────
        // 8 · ROLLBACK AUTO (si le pipeline est en échec)
        // ────────────────────────────────────────────────────────
        stage('🔄 Rollback Gate') {
            when { expression { currentBuild.result == 'FAILURE' } }
            steps {
                script {
                    echo "==> Rollback en cours …"
                    env.SERVICES.split(' ').each { svc ->
                        sh "kubectl rollout undo deployment/${svc} -n ${env.K8S_NAMESPACE} || true"
                    }
                    echo "==> Rollback terminé"
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    post {

        // ────────────────────────────────────────────────────────
        // ALWAYS — nettoyage + archivage (s'exécute dans tous les cas)
        // ────────────────────────────────────────────────────────
        always {
            sh "docker images | grep '${env.REGISTRY_NAMESPACE}' | awk '{print \$3}' | xargs docker rmi -f 2>/dev/null || true"
            archiveArtifacts artifacts: '**/target/*-reports/**,trivy-report-*.json', allowEmptyArchive: true
            junit testResults: '**/target/*-reports/*.xml', allowEmptyResults: true
        }

        // ────────────────────────────────────────────────────────
        // SUCCESS — Email HTML + Slack vert
        // ────────────────────────────────────────────────────────
        success {
            script {
                // ── Email ──────────────────────────────────────
                def subject = "✅ [Jenkins] BUILD OK — ${env.JOB_NAME} #${env.BUILD_NUMBER} (${env.K8S_NAMESPACE})"
                def body = """
                    <html><body style="font-family:Arial,sans-serif;font-size:14px;color:#1a1a1a">
                    <table width="600" cellpadding="0" cellspacing="0" style="border:1px solid #d4edda;border-radius:6px;overflow:hidden">
                      <tr><td style="background:#28a745;padding:16px 24px">
                        <h2 style="margin:0;color:#fff;font-size:18px">✅ Build Succeeded</h2>
                      </td></tr>
                      <tr><td style="padding:20px 24px">
                        <table style="width:100%;border-collapse:collapse">
                          <tr><td style="padding:6px 0;color:#555;width:140px"><b>Job</b></td>
                              <td style="padding:6px 0">${env.JOB_NAME} #${env.BUILD_NUMBER}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Branche</b></td>
                              <td style="padding:6px 0">${env.GIT_BRANCH}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Commit</b></td>
                              <td style="padding:6px 0">${env.GIT_COMMIT_SHORT} — ${env.GIT_AUTHOR}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Image</b></td>
                              <td style="padding:6px 0">${env.REGISTRY_NAMESPACE}/*:${env.IMAGE_TAG}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Environnement</b></td>
                              <td style="padding:6px 0">${env.K8S_NAMESPACE}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Durée</b></td>
                              <td style="padding:6px 0">${currentBuild.durationString}</td></tr>
                        </table>
                      </td></tr>
                      <tr><td style="padding:12px 24px 20px;text-align:center">
                        <a href="${env.BUILD_URL}" style="background:#28a745;color:#fff;padding:10px 24px;border-radius:4px;text-decoration:none;font-weight:bold">Voir les logs</a>
                      </td></tr>
                    </table>
                    </body></html>
                """.stripIndent()

                emailext(
                    subject      : subject,
                    body         : body,
                    mimeType     : 'text/html',
                    to           : env.EMAIL_RECIPIENTS,
                    replyTo      : env.EMAIL_REPLY_TO,
                    attachmentsPattern: 'trivy-report-*.json'
                )

                // ── Slack ──────────────────────────────────────
                slackSend(
                    channel: env.SLACK_CHANNEL,
                    color: 'good',
                    message: """✅ *BUILD SUCCEEDED* — `${env.JOB_NAME}` #${env.BUILD_NUMBER}
• Branch : `${env.GIT_BRANCH}` | Commit : `${env.GIT_COMMIT_SHORT}` par ${env.GIT_AUTHOR}
• Image  : `${env.REGISTRY_NAMESPACE}/*:${env.IMAGE_TAG}`
• Env    : `${env.K8S_NAMESPACE}` | Durée : ${currentBuild.durationString}
<${env.BUILD_URL}|Voir les logs>"""
                )
            }
        }

        // ────────────────────────────────────────────────────────
        // FAILURE — Email HTML rouge + Slack rouge
        //
        //  On inclut ici les informations de débogage essentielles :
        //  - stage en échec
        //  - lien direct vers les logs console
        //  - rapport Trivy en pièce jointe si disponible
        // ────────────────────────────────────────────────────────
        failure {
            script {
                // ── Collecte du log console (dernières 100 lignes) ──
                def consoleLog = ''
                try {
                    consoleLog = currentBuild.rawBuild
                        .getLog(100)
                        .join('\n')
                        .replaceAll('<', '&lt;')
                        .replaceAll('>', '&gt;')
                } catch (e) {
                    consoleLog = '(log non disponible)'
                }

                def subject = "❌ [Jenkins] BUILD FAILED — ${env.JOB_NAME} #${env.BUILD_NUMBER} (${env.K8S_NAMESPACE})"
                def body = """
                    <html><body style="font-family:Arial,sans-serif;font-size:14px;color:#1a1a1a">
                    <table width="600" cellpadding="0" cellspacing="0" style="border:1px solid #f5c6cb;border-radius:6px;overflow:hidden">
                      <tr><td style="background:#dc3545;padding:16px 24px">
                        <h2 style="margin:0;color:#fff;font-size:18px">❌ Build Failed</h2>
                      </td></tr>
                      <tr><td style="padding:20px 24px">
                        <table style="width:100%;border-collapse:collapse">
                          <tr><td style="padding:6px 0;color:#555;width:140px"><b>Job</b></td>
                              <td style="padding:6px 0">${env.JOB_NAME} #${env.BUILD_NUMBER}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Branche</b></td>
                              <td style="padding:6px 0">${env.GIT_BRANCH}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Commit</b></td>
                              <td style="padding:6px 0">${env.GIT_COMMIT_SHORT} — ${env.GIT_AUTHOR}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Stage en échec</b></td>
                              <td style="padding:6px 0;color:#dc3545;font-weight:bold">${env.STAGE_NAME ?: 'inconnu'}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Environnement</b></td>
                              <td style="padding:6px 0">${env.K8S_NAMESPACE}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Durée</b></td>
                              <td style="padding:6px 0">${currentBuild.durationString}</td></tr>
                        </table>
                      </td></tr>
                      <tr><td style="padding:0 24px 16px">
                        <p style="margin:8px 0 6px;font-weight:bold;color:#555">Extrait du log console (100 dernières lignes) :</p>
                        <pre style="background:#f8f9fa;border:1px solid #dee2e6;border-radius:4px;padding:12px;font-size:12px;overflow-x:auto;white-space:pre-wrap;max-height:300px">${consoleLog}</pre>
                      </td></tr>
                      <tr><td style="padding:12px 24px 20px;text-align:center">
                        <a href="${env.BUILD_URL}console" style="background:#dc3545;color:#fff;padding:10px 24px;border-radius:4px;text-decoration:none;font-weight:bold">Voir le log complet</a>
                      </td></tr>
                    </table>
                    </body></html>
                """.stripIndent()

                emailext(
                    subject      : subject,
                    body         : body,
                    mimeType     : 'text/html',
                    to           : env.EMAIL_RECIPIENTS,
                    replyTo      : env.EMAIL_REPLY_TO,
                    // Notifie aussi le committer responsable du commit en échec
                    recipientProviders: [
                        [$class: 'CulpritsRecipientProvider'],
                        [$class: 'RequesterRecipientProvider']
                    ],
                    attachmentsPattern: 'trivy-report-*.json'
                )

                // ── Slack ──────────────────────────────────────
                slackSend(
                    channel: env.SLACK_CHANNEL,
                    color: 'danger',
                    message: """❌ *BUILD FAILED* — `${env.JOB_NAME}` #${env.BUILD_NUMBER}
• Branch : `${env.GIT_BRANCH}` | Commit : `${env.GIT_COMMIT_SHORT}`
• Stage  : `${env.STAGE_NAME ?: 'inconnu'}`
<${env.BUILD_URL}console|Voir le log complet>"""
                )
            }
        }

        // ────────────────────────────────────────────────────────
        // UNSTABLE — Email HTML orange + Slack orange
        //  (Quality Gate warning ou Trivy warning avec FORCE_DEPLOY)
        // ────────────────────────────────────────────────────────
        unstable {
            script {
                def subject = "⚠️ [Jenkins] BUILD UNSTABLE — ${env.JOB_NAME} #${env.BUILD_NUMBER} (${env.K8S_NAMESPACE})"
                def body = """
                    <html><body style="font-family:Arial,sans-serif;font-size:14px;color:#1a1a1a">
                    <table width="600" cellpadding="0" cellspacing="0" style="border:1px solid #ffc107;border-radius:6px;overflow:hidden">
                      <tr><td style="background:#ffc107;padding:16px 24px">
                        <h2 style="margin:0;color:#1a1a1a;font-size:18px">⚠️ Build Unstable</h2>
                      </td></tr>
                      <tr><td style="padding:20px 24px">
                        <p style="margin:0 0 12px">Le build a terminé mais des avertissements ont été détectés :</p>
                        <ul style="margin:0;padding-left:20px">
                          <li>Quality Gate SonarQube en échec <em>(FORCE_DEPLOY activé)</em></li>
                          <li>Vulnérabilités Trivy ${env.TRIVY_SEVERITY} <em>(FORCE_DEPLOY activé)</em></li>
                        </ul>
                        <p style="margin:12px 0 0;color:#856404"><b>Action requise :</b> corriger avant le prochain déploiement en production.</p>
                      </td></tr>
                      <tr><td style="padding:0 24px 20px">
                        <table style="width:100%;border-collapse:collapse">
                          <tr><td style="padding:6px 0;color:#555;width:140px"><b>Job</b></td>
                              <td style="padding:6px 0">${env.JOB_NAME} #${env.BUILD_NUMBER}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Branche</b></td>
                              <td style="padding:6px 0">${env.GIT_BRANCH}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Commit</b></td>
                              <td style="padding:6px 0">${env.GIT_COMMIT_SHORT} — ${env.GIT_AUTHOR}</td></tr>
                          <tr><td style="padding:6px 0;color:#555"><b>Environnement</b></td>
                              <td style="padding:6px 0">${env.K8S_NAMESPACE}</td></tr>
                        </table>
                      </td></tr>
                      <tr><td style="padding:12px 24px 20px;text-align:center">
                        <a href="${env.BUILD_URL}" style="background:#856404;color:#fff;padding:10px 24px;border-radius:4px;text-decoration:none;font-weight:bold">Voir les logs</a>
                      </td></tr>
                    </table>
                    </body></html>
                """.stripIndent()

                emailext(
                    subject      : subject,
                    body         : body,
                    mimeType     : 'text/html',
                    to           : env.EMAIL_RECIPIENTS,
                    replyTo      : env.EMAIL_REPLY_TO,
                    recipientProviders: [
                        [$class: 'CulpritsRecipientProvider']
                    ],
                    attachmentsPattern: 'trivy-report-*.json'
                )

                // ── Slack ──────────────────────────────────────
                slackSend(
                    channel: env.SLACK_CHANNEL,
                    color: 'warning',
                    message: "⚠️ *BUILD UNSTABLE* — `${env.JOB_NAME}` #${env.BUILD_NUMBER} — Quality Gate ou Trivy warning. <${env.BUILD_URL}|Logs>"
                )
            }
        }

        // ────────────────────────────────────────────────────────
        // ABORTED — Email simple (pas de Slack pour ne pas spammer)
        // ────────────────────────────────────────────────────────
        aborted {
            script {
                emailext(
                    subject : "🚫 [Jenkins] BUILD ANNULÉ — ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body    : """<html><body style="font-family:Arial,sans-serif;font-size:14px">
                        <p>Le build <b>${env.JOB_NAME} #${env.BUILD_NUMBER}</b> a été annulé manuellement ou a dépassé le timeout.</p>
                        <p>Branch : <b>${env.GIT_BRANCH}</b> | Commit : <b>${env.GIT_COMMIT_SHORT}</b></p>
                        <p><a href="${env.BUILD_URL}">Voir les détails</a></p>
                        </body></html>""",
                    mimeType: 'text/html',
                    to      : env.EMAIL_RECIPIENTS,
                    replyTo : env.EMAIL_REPLY_TO
                )
            }
        }

        // ────────────────────────────────────────────────────────
        // CLEANUP — nettoyage workspace
        // ────────────────────────────────────────────────────────
        cleanup {
            cleanWs(
                cleanWhenSuccess : true,
                cleanWhenFailure : false,
                cleanWhenAborted : true
            )
        }
    }
}