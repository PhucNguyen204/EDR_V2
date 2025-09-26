import React from 'react';
import { Card, Alert, Button, Collapse } from 'antd';
import { BugOutlined, ReloadOutlined } from '@ant-design/icons';
import { useQuery } from 'react-query';
import { alertsAPI, statsAPI, rulesAPI, endpointsAPI } from '../services/api';

const { Panel } = Collapse;

const DebugAPI = () => {
  const { data: stats, isLoading: statsLoading, error: statsError } = useQuery(
    'debug-stats',
    statsAPI.getStats
  );

  const { data: alerts, isLoading: alertsLoading, error: alertsError } = useQuery(
    'debug-alerts',
    () => alertsAPI.getAlerts(5)
  );

  const { data: rules, isLoading: rulesLoading, error: rulesError } = useQuery(
    'debug-rules',
    rulesAPI.getRules
  );

  const { data: endpoints, isLoading: endpointsLoading, error: endpointsError } = useQuery(
    'debug-endpoints',
    endpointsAPI.getEndpoints
  );

  const getStatusColor = (loading, error, data) => {
    if (loading) return 'blue';
    if (error) return 'red';
    if (data) return 'green';
    return 'gray';
  };

  const getStatusText = (loading, error, data) => {
    if (loading) return 'Loading...';
    if (error) return `Error: ${error.message}`;
    if (data) return `Success: ${Array.isArray(data) ? data.length : 'Object'} items`;
    return 'No data';
  };

  return (
    <Card
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <BugOutlined />
          API Debug Information
        </div>
      }
    >
      <Collapse defaultActiveKey={['stats']}>
        <Panel header="Stats API" key="stats">
          <Alert
            message="Stats API"
            description={
              <div>
                <p>Status: {getStatusText(statsLoading, statsError, stats)}</p>
                <p>Data Type: {typeof stats}</p>
                <p>Is Array: {Array.isArray(stats) ? 'Yes' : 'No'}</p>
                {stats && (
                  <pre style={{ fontSize: '12px', marginTop: 10 }}>
                    {JSON.stringify(stats, null, 2)}
                  </pre>
                )}
              </div>
            }
            type={statsError ? 'error' : statsLoading ? 'info' : 'success'}
            showIcon
          />
        </Panel>

        <Panel header="Alerts API" key="alerts">
          <Alert
            message="Alerts API"
            description={
              <div>
                <p>Status: {getStatusText(alertsLoading, alertsError, alerts)}</p>
                <p>Data Type: {typeof alerts}</p>
                <p>Is Array: {Array.isArray(alerts) ? 'Yes' : 'No'}</p>
                {alerts && (
                  <pre style={{ fontSize: '12px', marginTop: 10 }}>
                    {JSON.stringify(Array.isArray(alerts) ? alerts.slice(0, 2) : alerts, null, 2)}
                  </pre>
                )}
              </div>
            }
            type={alertsError ? 'error' : alertsLoading ? 'info' : 'success'}
            showIcon
          />
        </Panel>

        <Panel header="Rules API" key="rules">
          <Alert
            message="Rules API"
            description={
              <div>
                <p>Status: {getStatusText(rulesLoading, rulesError, rules)}</p>
                <p>Data Type: {typeof rules}</p>
                <p>Is Array: {Array.isArray(rules) ? 'Yes' : 'No'}</p>
                {rules && (
                  <pre style={{ fontSize: '12px', marginTop: 10 }}>
                    {JSON.stringify(Array.isArray(rules) ? rules.slice(0, 2) : rules, null, 2)}
                  </pre>
                )}
              </div>
            }
            type={rulesError ? 'error' : rulesLoading ? 'info' : 'success'}
            showIcon
          />
        </Panel>

        <Panel header="Endpoints API" key="endpoints">
          <Alert
            message="Endpoints API"
            description={
              <div>
                <p>Status: {getStatusText(endpointsLoading, endpointsError, endpoints)}</p>
                <p>Data Type: {typeof endpoints}</p>
                <p>Is Array: {Array.isArray(endpoints) ? 'Yes' : 'No'}</p>
                {endpoints && (
                  <pre style={{ fontSize: '12px', marginTop: 10 }}>
                    {JSON.stringify(Array.isArray(endpoints) ? endpoints.slice(0, 2) : endpoints, null, 2)}
                  </pre>
                )}
              </div>
            }
            type={endpointsError ? 'error' : endpointsLoading ? 'info' : 'success'}
            showIcon
          />
        </Panel>
      </Collapse>
    </Card>
  );
};

export default DebugAPI;
