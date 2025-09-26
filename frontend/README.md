# EDR Dashboard Frontend

React-based frontend for the EDR (Endpoint Detection and Response) system.

## Features

- **Dashboard**: Overview of security metrics, recent alerts, and system status
- **Alerts**: View and manage security alerts with filtering and search
- **Process Tree**: Visualize process relationships and identify suspicious activities
- **Rules**: Manage detection rules and their configurations
- **Endpoints**: Monitor connected endpoints and their status

## Prerequisites

- Node.js 16+ 
- npm or yarn
- EDR Backend running on http://localhost:8080

## Installation

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm start
```

3. Open http://localhost:3000 in your browser

## Build for Production

```bash
npm run build
```

## API Endpoints

The frontend connects to the EDR backend API:

- `GET /api/v1/detections` - Get security alerts
- `GET /api/v1/endpoints` - Get connected endpoints
- `GET /api/v1/process_tree` - Get process tree data
- `GET /api/v1/rules` - Get detection rules
- `GET /api/v1/stats` - Get system statistics

## Components

- **Dashboard**: Main overview with statistics and recent alerts
- **Alerts**: Alert management with filtering and detailed views
- **ProcessTree**: Process visualization with suspicious activity detection
- **Rules**: Rule management interface
- **Endpoints**: Endpoint monitoring and status

## Technologies Used

- React 18
- Ant Design (UI components)
- React Query (data fetching)
- React Router (navigation)
- Recharts (data visualization)
- Axios (HTTP client)
