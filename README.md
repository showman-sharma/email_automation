# Email Automation

This repository contains scripts for automating email processing using the Gmail API. The core script, `email_automation.py`, processes incoming emails, categorizes them based on their content, and responds automatically. It integrates with MongoDB to check registered users and with Cohere for natural language classification. Additionally, the `token_generator.py` script handles the initial setup of Google API credentials and tokens.

## Table of Contents

1. [Features](#features)
2. [Getting Started](#getting-started)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Running the Scripts](#running-the-scripts)
6. [Setting up Google API Tokens](#setting-up-google-api-tokens)
7. [Environment Variables](#environment-variables)
8. [GitHub Actions](#github-actions)
9. [License](#license)

## Features

- Automatically processes unread emails from a Gmail account.
- Classifies emails using Cohere API and responds accordingly.
- Integrates with MongoDB to check for registered users.
- Handles email forwarding to a manual support team for emails that fall into the "other" category.
- Works with GitHub Actions for continuous deployment.
- Utilizes Google API tokens stored locally or in environment variables for authentication.

## Getting Started

To get the project running, follow the steps below.

## Prerequisites

Make sure you have the following installed:

1. **Python 3.x**
2. **Google API Client Library** for Python
3. **Cohere API** for classification
4. **MongoDB Atlas** or any MongoDB instance
5. **GitHub account** with repository setup

### Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/showman-sharma/email_automation.git
   cd email_automation
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Set up **Google API Credentials** and **MongoDB** environment variables (explained in the next sections).

## Running the Scripts

### 1. `token_generator.py`

This script generates the `token.pickle` and `token.json` files for authenticating with Gmail using OAuth 2.0.

#### Steps:

1. Ensure you have a `credentials.json` file from the Google Cloud Console. Follow [this guide](https://developers.google.com/gmail/api/quickstart/python) to create and download your credentials.

2. Run the script to generate the token:

   ```bash
   python token_generator.py
   ```

   This will launch a browser window where you can authenticate and authorize the application.

3. Once authenticated, the script will generate `token.pickle` and `token.json`. These files store your access and refresh tokens, allowing the app to authenticate without requiring user login each time.

### 2. `email_automation.py`

This is the main script that processes unread emails, categorizes them using the Cohere API, and responds or forwards the email.

#### Run the script:

```bash
python email_automation.py
```

Ensure that the necessary environment variables are set (explained below) before running the script.

## Setting up Google API Tokens

To interact with the Gmail API, you need to set up OAuth 2.0 credentials:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project.
3. Enable the **Gmail API**.
4. Go to **APIs & Services > Credentials**, and create OAuth 2.0 credentials.
5. Download the `credentials.json` file and place it in the root directory of this project.

### Token Generation

Run `token_generator.py` to generate the required tokens:

```bash
python token_generator.py
```

This will generate `token.pickle` and `token.json`, which store your Google OAuth tokens for further use in the automation script.

## Environment Variables

You will need to define the following environment variables for both local use and GitHub Actions:

| Variable                | Description                                                  | Example                      |
| ----------------------- | ------------------------------------------------------------ | ---------------------------- |
| `GOOGLE_CREDENTIALS`     | JSON string containing Google credentials data.              | Content from `token.json`     |
| `MONGO_USERNAME`         | MongoDB Atlas username.                                      | `myusername`                  |
| `MONGO_PASSWORD`         | MongoDB Atlas password.                                      | `mypassword`                  |
| `COHERE_API_KEY`         | Your Cohere API key for classification.                      | `abcdef12345`                 |
| `MANUAL_SUPPORT_EMAIL_ID`| Email ID where unclassified emails will be forwarded.        | `support@yourdomain.com`      |
| `SUPPORT_EMAIL_ID`       | The email address from which automated responses are sent.   | `no-reply@yourdomain.com`     |

### Create a `.env` File (Optional)

You can store your environment variables in a `.env` file for local testing:

```
GOOGLE_CREDENTIALS={"token": "...", "refresh_token": "...", "client_id": "...", "client_secret": "..."}
MONGO_USERNAME=your_mongo_username
MONGO_PASSWORD=your_mongo_password
COHERE_API_KEY=your_cohere_api_key
MANUAL_SUPPORT_EMAIL_ID=support@yourdomain.com
SUPPORT_EMAIL_ID=no-reply@yourdomain.com
```

Then, use `python-dotenv` to load these variables into your script.

## GitHub Actions

GitHub Actions is set up in this repository for continuous deployment.

### Setup GitHub Secrets:

Add the following secrets to your GitHub repository under **Settings > Secrets**:

1. `GOOGLE_CREDENTIALS`
2. `MONGO_USERNAME`
3. `MONGO_PASSWORD`
4. `COHERE_API_KEY`
5. `MANUAL_SUPPORT_EMAIL_ID`
6. `SUPPORT_EMAIL_ID`

### Workflow File (`.github/workflows/email_automation.yml`)

This workflow ensures your automation runs on schedule or based on any defined triggers. The existing workflow file in the repo looks like this:

```yaml
name: Email Automation

on:
  push:
    branches:
      - main
  schedule:
    - cron: "*/10 * * * *"  # Runs every 10 minutes

jobs:
  run-email-automation:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.x'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt

      - name: Run email automation
        env:
          GOOGLE_CREDENTIALS: ${{ secrets.GOOGLE_CREDENTIALS }}
          MONGO_USERNAME: ${{ secrets.MONGO_USERNAME }}
          MONGO_PASSWORD: ${{ secrets.MONGO_PASSWORD }}
          COHERE_API_KEY: ${{ secrets.COHERE_API_KEY }}
          MANUAL_SUPPORT_EMAIL_ID: ${{ secrets.MANUAL_SUPPORT_EMAIL_ID }}
          SUPPORT_EMAIL_ID: ${{ secrets.SUPPORT_EMAIL_ID }}
        run: |
          python email_automation.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
