# Getting Started with goYSFReflector

Welcome to the goYSFReflector documentation! This guide will help you set up and run your own YSF reflector using Go.

## Prerequisites

Before you start, ensure you have the following installed:

- **Go (1.18 or later)**: Download and install from the [official Go website](https://golang.org/dl/).
- **Git**: You can download it from [git-scm.com](https://git-scm.com/).

## Cloning the Repository

First, clone the `goYSFReflector` repository from GitHub:

```bash
git clone https://github.com/elteser/goYSFReflector.git
cd goYSFReflector
```

## Build the project

Change the udpPort to your needs. To build the project, run the following command:

```bash
go build
```

This will create an executable file named goYSFReflector.

## Running the Reflector

To run the reflector, execute the following command:

```bash
./goYSFReflector
```

You should see log messages indicating that the reflector is running and listening for incoming connections.

## Testing with netcat

