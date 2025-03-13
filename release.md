# Release Process

## Steps

1. Generate a formatted git tag from the desired state of the `main` branch by using the `tag.ps1` script located in the root of this repository:

   ```powershell
   .\tag.ps1
   ```

2. Push the tag to GitHub:

   ```text
   git push origin <tag>
   ```

   This will trigger a new release action run, that will perform build application and push it to `gh-pages` branch so it will be available for the one click installer.

3. Generate release on GitHub via UI, referencing tag
