# Release Process

This document outlines the steps required to create and publish a new release for the project.

## Steps

### 1. Generate a Git Tag

   To create a formatted Git tag based on the current state of the `main` branch, run the `tag.ps1` script located in the repository root:

   ```powershell
   .\tag.ps1
   ```

   This script will generate a new tag and associate it with the latest commit.

   **Example output**:

   ```powershell
   PS C:\AzureKeyVaultExplorer> .\tag.ps1
   Tag has been added: v2025.0314.1323.40
   ```

### 2. Push the Tag to GitHub

   Once the tag is created, push it to GitHub using the following command:

   ```powershell
   PS C:\AzureKeyVaultExplorer> git push origin <tag>
   ```

   **Example output**:

   ```powershell
   PS C:\AzureKeyVaultExplorer> git push origin v2025.0314.1323.40
   ```

   Pushing the tag will trigger a GitHub Actions workflow that:

- Builds the application and its installer.
- Creates a GitHub release with the generated installer as an artifact.

### 3. Verify and Publish the Release

   After the GitHub Actions workflow completes, navigate to the GitHub Releases page, review the automatically generated release draft, and publish it.
