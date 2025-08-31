
package azure.cis.fileshares

# --- 10.1.1 Ensure soft delete for Azure File Shares is Enabled ---
deny[msg] if {
  fs := data.azure_storage_file_shares[_]
  not fs.properties.shareDeleteRetentionPolicy.enabled
  msg := sprintf("CIS 10.1.1 Violation: Soft delete not enabled for File Share %s.", [fs.name])
}

# --- 10.1.2 Ensure SMB protocol version is set to SMB 3.1.1 or higher ---
deny[msg] if {
  fs := data.azure_storage_file_shares[_]
  version := fs.properties.protocols.smb
  not valid_smb_version(version)
  msg := sprintf("CIS 10.1.2 Violation: SMB protocol version %s is not >= SMB 3.1.1 for File Share %s.", [version, fs.name])
}

valid_smb_version(version) if {
  version == "3.1.1"
}

# --- 10.1.3 Ensure SMB channel encryption is set to AES-256-GCM or higher ---
deny[msg] if {
  fs := data.azure_storage_file_shares[_]
  encryption := fs.properties.encryption.smb.channel
  not valid_encryption(encryption)
  msg := sprintf("CIS 10.1.3 Violation: SMB channel encryption %s is not AES-256-GCM or higher for File Share %s.", [encryption, fs.name])
}

valid_encryption(enc) if {
  enc == "AES-256-GCM"
}
