pipeline {
    agent any
    stages {
        stage('Checkout Code') {
            steps {
                // Clones the repository containing these scripts
                checkout scm
            }
        }

        stage('Query Azure Infra State') {
            steps {
                script {
                withCredentials([
                    string(credentialsId: 'AZURE_CLIENT_ID', variable: 'AZURE_CLIENT_ID'),
                    string(credentialsId: 'AZURE_CLIENT_SECRET', variable: 'AZURE_CLIENT_SECRET'),
                    string(credentialsId: 'AZURE_TENANT_ID', variable: 'AZURE_TENANT_ID'),
                    string(credentialsId: 'AZURE_SUBSCRIPTION_ID', variable: 'AZURE_SUBSCRIPTION_ID')
                ]) {
                    sh 'az login --service-principal --username "$AZURE_CLIENT_ID" --password "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID"'
                    sh 'az account set --subscription "$AZURE_SUBSCRIPTION_ID"'
                }             
                    echo "Querying current Azure infrastructure state using Azure Resource Graph..."
                        sh 'chmod +x ./scripts/query_azure_infra.sh'
                        sh './scripts/query_azure_infra.sh'
                    }
                    // Archive the state file for later inspection if needed
                    archiveArtifacts artifacts: 'output/*.json'
                }
            }

   stage('Validate CIS') {
      steps {
        sh 'python3 scripts/validate_cis.py > output/cis_drifts_py.json'
      }
    }
    stage('OPA Policy Validation') {
      steps {
        sh 'opa test policy/azure/cis.rego'
        sh 'opa eval --input output/azure.json --data policy/azure/cis.rego "data.azure.cis.fileshares.deny"'
      }  
    }
        
        stage('Analyze for CIS Benchmark Drift') {
            steps {
                echo "Analyzing infrastructure state against CIS benchmarks..."
                sh 'python3 ./scripts/analyze_drift.py'
                // Archive the drift report for auditing
                archiveArtifacts artifacts: 'drift_report.json'
                sh 'cat drift_report.json'
            }
        }

        stage('Generate Remediation Script') {
            steps {
                echo "Generating Azure CLI remediation script..."
                sh 'python3 ./scripts/generate_remediation.py'
                // Archive the generated script
                archiveArtifacts artifacts: 'remediate.sh'
                sh 'cat remediate.sh'
            }
        }

    stage('Upload Reports to Azure Storage') {
      steps {
        sh '''
          # Set variables - REPLACE WITH YOUR ACTUAL STORAGE KEY
          STORAGE_ACCOUNT="pramstore"
          CONTAINER="reports"
          STORAGE_ACCOUNT_KEY="Jwq7OewQuAyapJSnFilwqKVEg1SEqyVBO9XiElPgA7xqWQTekTsHnUDQhZkwwsvBFdQxfac22h+u+ASth14AvA=="
          
          # Check if files exist
          if [ ! -f drift_report.json ]; then echo "Error: drift_report.json not found"; exit 1; fi
          if [ ! -f output/azure.json ]; then echo "Error: azure.json not found"; exit 1; fi
          
          # Upload to build-specific path
          az storage blob upload --container-name $CONTAINER --name "builds/$BUILD_NUMBER/drift_report.json" --file drift_report.json --account-name $STORAGE_ACCOUNT --account-key "$STORAGE_ACCOUNT_KEY" --overwrite
          az storage blob upload --container-name $CONTAINER --name "builds/$BUILD_NUMBER/azure.json" --file output/azure.json --account-name $STORAGE_ACCOUNT --account-key "$STORAGE_ACCOUNT_KEY" --overwrite
          
          # Upload to 'latest' path
          az storage blob upload --container-name $CONTAINER --name "latest/drift_report.json" --file drift_report.json --account-name $STORAGE_ACCOUNT --account-key "$STORAGE_ACCOUNT_KEY" --overwrite
          az storage blob upload --container-name $CONTAINER --name "latest/azure.json" --file output/azure.json --account-name $STORAGE_ACCOUNT --account-key "$STORAGE_ACCOUNT_KEY" --overwrite
        '''
      }
    }        
    }
}



