import React from 'react';
import { Card, Button, Alert, Spin } from 'antd';
import { useQuery } from 'react-query';
import { alertsAPI, statsAPI } from '../services/api';

const TestAPI = () => {
  const { data: stats, isLoading: statsLoading, error: statsError } = useQuery(
    'test-stats',
    statsAPI.getStats
  );

  const { data: alerts, isLoading: alertsLoading, error: alertsError } = useQuery(
    'test-alerts',
    () => alertsAPI.getAlerts(5)
  );

  if (statsLoading || alertsLoading) {
    return (
      <Card title="Testing API Connection">
        <Spin size="large" />
      </Card>
    );
  }

  return (
    <Card title="API Test Results">
      <div style={{ marginBottom: 16 }}>
        <h3>Stats API:</h3>
        {statsError ? (
          <Alert message="Stats API Error" description={statsError.message} type="error" />
        ) : (
          <div>
            <p>✅ Stats API working</p>
            <p>Rules: {stats?.rule_count || 0}</p>
            <p>Nodes: {stats?.node_count || 0}</p>
            <p>Correlation Windows: {stats?.correlation_windows || 0}</p>
          </div>
        )}
      </div>

      <div>
        <h3>Alerts API:</h3>
        {alertsError ? (
          <Alert message="Alerts API Error" description={alertsError.message} type="error" />
        ) : (
          <div>
            <p>✅ Alerts API working</p>
            <p>Found {alerts?.length || 0} alerts</p>
            {alerts && alerts.length > 0 && (
              <div>
                <p>First alert: {alerts[0].rule_name}</p>
                <p>Severity: {alerts[0].severity}</p>
                <p>Time: {new Date(alerts[0].occurred_at).toLocaleString()}</p>
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  );
};

export default TestAPI;
