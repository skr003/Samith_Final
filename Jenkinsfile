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

   stage('Validate PCI DSS') {
      steps {
        sh 'python3 scripts/validate_pci_dss.py > output/pci_drifts_py.json'
      }
    }
    stage('OPA Policy Validation') {
      steps {
        sh 'opa test policy/azure/pci_dss.rego'
        sh 'opa eval --input output/azure.json --data policy/azure/pci_dss.rego "data.azure.pci_dss.fileshares.deny"'
      }  
    }
        
        stage('Analyze for PCI_DSS Benchmark Drift') {
            steps {
                echo "Analyzing infrastructure state against PCI_DSS benchmarks..."
                sh 'python3 ./scripts/analyze_drift.py'
                // Archive the drift report for auditing
                archiveArtifacts artifacts: 'drift_report.json'
                sh 'cat drift_report.json'
            }
        }

    stage('Upload Reports to Azure Storage') {
      steps {
        sh '''
          # Set variables - REPLACE WITH YOUR ACTUAL STORAGE KEY
          STORAGE_ACCOUNT="reportingpcidss25655"
          CONTAINER="reports"
          STORAGE_ACCOUNT_KEY="pUsU+U4ZVzYx5jVJAyiEXeVIhgel/4iGxqYl+cY1WSJI5NKsvlbYN5Si9NXHr8TKQTB92BHvTH64+AStjLZLuQ=="
          
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






