# Get the MCP server

The DocSpace MCP server can be obtained in several ways depending on your environment and requirements.

## Choosing a distribution method

Before choosing a distribution method, consult the following table:

| **I want to**                                | **Recommended method**         |
|----------------------------------------------|--------------------------------|
| Get started quickly with minimal setup       | Docker Hub, npm Registry       |
| Run in an isolated, reproducible environment | Docker Hub, Docker MCP Toolkit |
| Use a GUI to manage everything               | Docker MCP Toolkit             |
| Install a specific version offline           | GitHub releases                |
| Customize or contribute to the server        | Build from source              |

> **Tip:** We recommend Docker Hub as it offers a minimal, easy setup to get started, in addition to an isolated environment.

## Build the MCP server from source

This method is ideal for developers who want to customize or contribute to the project. You can build from source using three methods, with each having its own prerequisites:

| **Build**  | **Prerequisites**                             |
|------------|-----------------------------------------------|
| Docker     | Docker                                        |
| Node.js    | pnpm (v10 or higher), Node.js (v24 or higher) |
| MCP bundle | pnpm (v10 or higher), Node.js (v24 or higher) |

### Docker image

1. Clone the repository from the ONLYOFFICE Git server:

```sh
git clone git@git.onlyoffice.com:ONLYOFFICE/docspace-mcp.git
```

   Alternatively, clone from the GitHub mirror:

```sh
git clone git@github.com:ONLYOFFICE/docspace-mcp.git
```

2. Navigate to the project directory:

```sh
cd docspace-mcp
```

3. Build the Docker image:

```sh
docker build --tag onlyoffice/docspace-mcp .
```

4. Run the Docker container:

```sh
docker run --interactive --rm onlyoffice/docspace-mcp
```

### Node.js app

1. Clone the repository from the ONLYOFFICE Git server:

```sh
git clone git@git.onlyoffice.com:ONLYOFFICE/docspace-mcp.git
```

   Alternatively, clone from the GitHub mirror:

```sh
git clone git@github.com:ONLYOFFICE/docspace-mcp.git
```

2. Navigate to the project directory:

```sh
cd docspace-mcp
```

3. Build the Node.js application:

```sh
pnpm build-app
```

4. Run the Node.js application:

```sh
./bin/onlyoffice-docspace-mcp
```

### MCP bundle

1. Clone the repository from the ONLYOFFICE Git server:

```sh
git clone git@git.onlyoffice.com:ONLYOFFICE/docspace-mcp.git
```

   Alternatively, clone from the GitHub mirror:

```sh
git clone git@github.com:ONLYOFFICE/docspace-mcp.git
```

2. Navigate to the project directory:

```sh
cd docspace-mcp
```

3. Build the MCP bundle:

```sh
pnpm build-mcpb
```

4. Use the built `.mcpb` file from the root of the project directory in an
   application that supports MCP bundles.

## Pull from Docker Hub

This method is ideal for developers who want a consistent, isolated runtime environment with minimal setup. Before starting:

- Ensure you have [Docker](https://www.docker.com/) installed on your system.

1. Pull the latest [DocSpace MCP server image](https://hub.docker.com/r/onlyoffice/docspace-mcp) from Docker Hub:

   ```sh
   docker pull onlyoffice/docspace-mcp
   ```

   To pull a specific version:

   ```sh
   docker pull onlyoffice/docspace-mcp:<version>
   ```

2. Run the Docker container:

   ```sh
   docker run --interactive --rm onlyoffice/docspace-mcp
   ```

## Build with Docker MCP Toolkit

This method works best for non-technical users or users who prefer a graphical interface over the command line. Before proceeding, ensure you have:

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) with the [Docker MCP Toolkit](https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/) enabled


1. Enable the Docker MCP Toolkit by following the [Enable Docker MCP Toolkit](https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/#enable-docker-mcp-toolkit) guide.

2. Install the DocSpace MCP server through the Docker Desktop interface using the [Install an MCP Server](https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/#install-an-mcp-server) guide, or by using the Docker CLI:

   ```sh
   docker mcp server enable onlyoffice-docspace
   ```

3. Connect the DocSpace MCP server to an MCP client through the Docker Desktop interface using the [Install an MCP Client](https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/#install-an-mcp-client) guide, or by using the Docker CLI:

   ```sh
   docker mcp client connect --global <client>
   ```

## Build with npm registry

This method also requires minimal setup and is ideal for developers who want the fastest setup with no containerization overhead. Ensure you have:

- [Node.js](https://nodejs.org/) version 18 or higher

1. Run the latest version of the DocSpace MCP server:

   ```sh
   npx --yes @onlyoffice/docspace-mcp
   ```

   To run a specific version:

   ```sh
   npx --yes @onlyoffice/docspace-mcp@<version>
   ```

2. Open a different terminal session and confirm the MCP server is running:

**For Linux/macOS**:

   ```sh
   ps aux | grep onlyoffice
   ```

   You should see a list of running `onlyoffice` processes.

The `ps aux` command lists all running processes, including those not attached to a terminal - like the MCP server, and then uses the `grep` command to filter the list for the running processes containing `onlyoffice`.

**For Windows**:

   ```powershell
   Get-Process | Where-Object { $_.Name -like "*onlyoffice*" }
   ```

`Get-Process` retrieves all running processes and then uses the `Where-Object` command to filter for processes with `onlyoffice`.

## Download the GitHub release

This method is ideal for teams who want to have access without pulling from a registry at runtime. This method also requires you to have [Node.js](https://nodejs.org/) version 18 or higher and is available in two formats:

- As an MCP bundle
- A Node.js application

### Download the MCP bundle GitHub release

Use this format if your MCP client supports `.mcpb` bundle files natively (e.g., Claude Desktop Extensions).

1. Download the latest release:

   ```sh
   VERSION=3.1.0 curl --location --output docspace-mcp.mcpb https://github.com/ONLYOFFICE/docspace-mcp/releases/download/v$VERSION/onlyoffice-docspace-mcp-$VERSION.mcpb
   ```

   To download a specific version:

   ```sh
   VERSION=<version> curl --location --output docspace-mcp.mcpb https://github.com/ONLYOFFICE/docspace-mcp/releases/download/v$VERSION/onlyoffice-docspace-mcp-$VERSION.mcpb
   ```

2. Use the downloaded `.mcpb` file in an application that supports MCP bundles.

### Download the Node.js app GitHub release

Use this format if you prefer to run the server as a standard Node.js process.

1. Download the latest release:

   ```sh
   VERSION=3.1.0 curl --location --output docspace-mcp.tgz https://github.com/ONLYOFFICE/docspace-mcp/releases/download/v$VERSION/onlyoffice-docspace-mcp-$VERSION.tgz
   ```

   To download a specific version:

   ```sh
   VERSION=<version> curl --location --output docspace-mcp.tgz https://github.com/ONLYOFFICE/docspace-mcp/releases/download/v$VERSION/onlyoffice-docspace-mcp-$VERSION.tgz
   ```

2. Extract the downloaded archive:

   ```sh
   tar --extract --gzip --file docspace-mcp.tgz
   ```

3. Navigate to the extracted directory:

   ```sh
   cd docspace-mcp
   ```

4. Run the Node.js application:

   ```sh
   ./bin/onlyoffice-docspace-mcp
   ```

## After getting the server

- Learn how to [connect the MCP server to MCP clients](../getting-started/clients.md)
