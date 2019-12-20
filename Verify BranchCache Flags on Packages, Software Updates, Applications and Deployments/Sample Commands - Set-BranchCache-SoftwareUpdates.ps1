# Gather info about all software updates
.\Set-BranchCache-SoftwareUpdates.ps1 -SiteServer CM01 -Mode Gather

# Disable BranchCache on all software updates
.\Set-BranchCache-SoftwareUpdates.ps1 -SiteServer CM01 -Mode Disable

# Enable BranchCache on all software updates
.\Set-BranchCache-SoftwareUpdates.ps1 -SiteServer CM01 -Mode Enable
