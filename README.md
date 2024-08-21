# Cyber Log Analyzer

Cyber Log Analyzer is an advanced Python tool designed to analyze server authentication logs and detect potential intrusion attempts. It scans log files for suspicious activities like brute-force attacks and unusual login patterns, and sends alerts when necessary.

## Features

- **Failed Login Detection**: Detects and alerts on multiple failed login attempts from the same IP address.
- **Successful Login Tracking**: Tracks successful logins and identifies unusual patterns.
- **Geolocation of IPs**: Identifies the geographical location of the IPs involved in suspicious activities.
- **Email Notifications**: Sends email alerts when suspicious activities are detected.
- **Customizable Reports**: Generates HTML or CSV reports with details about the detected activities.
- **Configurable via YAML**: Easily customizable thresholds, patterns, and report formats via a configuration file.
- **Enhanced Logging**: Includes detailed logging of operations and errors.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Titzn/cyber_log_analyzer.git
    cd cyber_log_analyzer
    ```

2. Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Configure the `config.yaml` file with your email, log file path, and other settings.

## Usage

Run the script to start analyzing logs:

    ```bash
    python log_analyzer.py --config=config.yaml
    ```

## Generating Reports

Reports will be generated in the `reports/` directory. You can specify the format of the report in the `config.yaml` file (`html` or `csv`).

## Testing

Run tests to ensure the functionality works as expected:

    ```bash
    pip install pytest
    pytest tests/
    ```

## Contribution

Contributions are welcome! Feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

[Titzn](https://github.com/Titzn)
