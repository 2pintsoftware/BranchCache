# Gather info about all packages
.\Set-BranchCache-Packages.ps1 -SiteServer CM01 -Mode Gather

# Disable BranchCache on all packages that have content
.\Set-BranchCache-Packages.ps1 -SiteServer CM01 -Mode Disable

# Enable BranchCache on all packages that have content
.\Set-BranchCache-Packages.ps1 -SiteServer CM01 -Mode Enable


# Gather info about individual package(s), wild cards supported
.\Set-BranchCache-Packages.ps1 -SiteServer CM01 -Mode Gather -PackageName "1 GB File 001"
.\Set-BranchCache-Packages.ps1 -SiteServer CM01 -Mode Gather -PackageName "*File*"

# Disable BranchCache on individual package(s), wild cards supported
.\Set-BranchCache-Packages.ps1 -SiteServer CM01 -Mode Disable -PackageName "1 GB File 001"
.\Set-BranchCache-Packages.ps1 -SiteServer CM01 -Mode Disable -PackageName "*File*"

# Enable BranchCache on individual package(s), wild cards supported
.\Set-BranchCache-Packages.ps1 -SiteServer CM01 -Mode Enable -PackageName "1 GB File 001"
.\Set-BranchCache-Packages.ps1 -SiteServer CM01 -Mode Enable -PackageName "*File*"