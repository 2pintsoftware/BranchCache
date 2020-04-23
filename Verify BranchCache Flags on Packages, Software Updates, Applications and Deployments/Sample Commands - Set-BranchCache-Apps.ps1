# Gather info about all apps
.\Set-BranchCache-Apps.ps1 -SiteServer CM01 -Mode Gather

# Disable BranchCache on all apps that have content
.\Set-BranchCache-Apps.ps1 -SiteServer CM01 -Mode Disable

# Enable BranchCache on all apps that have content
.\Set-BranchCache-Apps.ps1 -SiteServer CM01 -Mode Enable


# Gather info about individual app(s), wild cards supported
.\Set-BranchCache-Apps.ps1 -SiteServer CM01 -Mode Gather -AppName "Microsoft Office 2016"
.\Set-BranchCache-Apps.ps1 -SiteServer CM01 -Mode Gather -AppName "*Office*"

# Disable BranchCache on individual app(s), wild cards supported
.\Set-BranchCache-Apps.ps1 -SiteServer CM01 -Mode Disable -AppName "Microsoft Office 2016"
.\Set-BranchCache-Apps.ps1 -SiteServer CM01 -Mode Disable -AppName "*Office*"

# Enable BranchCache on individual app(s), wild cards supported
.\Set-BranchCache-Apps.ps1 -SiteServer CM01 -Mode Enable -AppName "Microsoft Office 2016"
.\Set-BranchCache-Apps.ps1 -SiteServer CM01 -Mode Enable -AppName "*Office*"
