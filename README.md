# Firmware Insights: AI-Powered Security Analysis

Firmware Insights is a web-based tool designed to perform in-depth security analysis on firmware files. By leveraging the power of generative AI, it can identify device components, uncover known vulnerabilities, detect hardcoded secrets, and discover potential zero-day threats from firmware binaries and bootlogs.

## Features

-   **Dual File Upload**: Analyze a firmware `.bin` file, a `bootlog.txt` file, or both together for a comprehensive analysis.
-   **AI-Enhanced Static Analysis**: Instead of just running `strings`, the application uses AI to perform an intelligent scan of the firmware's contents to:
    -   **Identify Device & Vendor**: Determines the device model, vendor, and type with a calculated confidence score.
    -   **Generate a Software Bill of Materials (SBOM)**: Detects software components and their versions (e.g., BusyBox 1.25.1, OpenSSL 1.1.1k).
    -   **Correlate CVEs**: Matches identified components against the National Vulnerability Database (NVD) to find known vulnerabilities.
    -   **Detect Hardcoded Secrets**: Scans for API keys, private keys, certificates, and username/password pairs.
    -   **Find Unsafe Code**: Identifies the use of insecure C functions (like `strcpy`) and weak cryptographic algorithms.
    -   **Discover Potential Vulnerabilities**: Analyzes configurations and scripts to find potential zero-day issues or backdoors.
-   **Interactive & Organized Reporting**: Presents findings in a clean, tab-based interface, allowing users to switch between AI-enhanced summaries and raw data for verification.
-   **Data Export**: The full analysis report can be exported as a JSON file.

## Tech Stack

-   **Framework**: [Next.js](https://nextjs.org/) (with App Router)
-   **UI**: [React](https://react.dev/), [ShadCN UI](https://ui.shadcn.com/), [Tailwind CSS](https://tailwindcss.com/)
-   **Generative AI**: [Google AI & Genkit](https://firebase.google.com/docs/genkit)
-   **Charts**: [Recharts](https://recharts.org/)

## Getting Started

### Prerequisites

-   [Node.js](https://nodejs.org/) (v20 or later)
-   A package manager like [npm](https://www.npmjs.com/) or [yarn](https://yarnpkg.com/).

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/Akash8451/Firmware-Insights
    ```
2.  Navigate to the project directory:
    ```bash
    cd Firmware-Insights
    ```
3.  Install the dependencies:
    ```bash
    npm install
    ```

### Running the Development Server

To start the development server, run:

```bash
npm run dev
```

Open the generated localhost link with your browser to see the result.

### Environment Variables

For CVE lookups against the NVD, you can optionally provide an API key to get a higher request rate. Create a `.env` file in the root of the project and add your key:

```
NVD_API_KEY=your-nvd-api-key-here
```

You can request an API key from the [NVD website](https://nvd.nist.gov/developers/request-an-api-key).
