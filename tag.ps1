# Get the latest commit ID and date in ISO format.
$gitOutput = git log -1 --pretty=format:"%h;%cd" --date=iso
$commitIdDate = $gitOutput.Split(';')
$commitDateUTC = [datetime]::Parse($commitIdDate[1]).ToUniversalTime()

# Generate the version string based on the commit date.
$versionString = $commitDateUTC.ToString("vyyyy.MMdd.HHmm.ss")

# Create a new git tag with the generated version string.
$existingTag = git tag --list $versionString
if ($existingTag) {
    Write-Output "No tag has been added."
    Write-Output "Tag already exists: $versionString"
} else {
    # Create a new git tag with the generated version string.
    git tag $versionString
    Write-Output "Tag has been added: $versionString"
}