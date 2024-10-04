# Contributing to Nexda

To contribute to the Nexda project, follow these steps:

1. Fork the repository:

```bash
git clone https://github.com/nexda-decompiler/nexda.git
cd nexda
```

2. Create a new branch for your feature or bug fix:
```bash
git checkout -b my-feature-branch
```

3. Propose changes:

Create a pull request for the branch so we can review your code and merge it if possible.

## A guide to contributing

To propperly contribute, follow these rules and constraints:

1. **Code style**: Follow the existing code style in the project. If you're unsure, you can use the `clang-format` file, by doing:
```bash
cd build
cmake ..
make format
```
This will ensure consistent code formatting.
2. **Check if your code is valid**: Check if your code works so you dont accidentally push unsafe code. We have workflows and checks that help identify issues before pushing it to the master branch.

3. **Commit messages**: Use clear and concise commit messages. Follow the standard commit message format.

## Help

If you still have questions about contributing, send us an email via our [GMail account.](mailto:rusindanilo@gmail.com)