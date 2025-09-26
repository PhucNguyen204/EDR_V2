import React, { useState, useEffect } from 'react';
import { Card, Button, Alert, Spin } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';

const SimpleTest = () => {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Test Stats API
      const statsResponse = await fetch('http://localhost:8080/api/v1/stats');
      const statsData = await statsResponse.json();
      setStats(statsData);
      
      // Test Alerts API
      const alertsResponse = await fetch('http://localhost:8080/api/v1/detections?limit=5');
      const alertsData = await alertsResponse.json();
      setAlerts(alertsData);
      
      console.log('Stats API Response:', statsData);
      console.log('Alerts API Response:', alertsData);
      
    } catch (err) {
      setError(err.message);
      console.error('API Error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <Card
      title="Simple API Test"
      extra={
        <Button 
          icon={<ReloadOutlined />} 
          onClick={fetchData}
          loading={loading}
        >
          Refresh
        </Button>
      }
    >
      {loading && <Spin size="large" />}
      
      {error && (
        <Alert
          message="API Error"
          description={error}
          type="error"
          showIcon
        />
      )}
      
      {stats && (
        <div style={{ marginBottom: 16 }}>
          <h3>Stats API Result:</h3>
          <p>✅ Rules: {stats.rule_count}</p>
          <p>✅ Nodes: {stats.node_count}</p>
          <p>✅ Correlation Windows: {stats.correlation_windows}</p>
        </div>
      )}
      
      {alerts && (
        <div>
          <h3>Alerts API Result:</h3>
          <p>✅ Found {alerts.length} detections</p>
          {alerts.length > 0 && (
            <div>
              <p>Latest: {alerts[0].rule_name}</p>
              <p>Severity: {alerts[0].severity}</p>
              <p>Time: {new Date(alerts[0].occurred_at).toLocaleString()}</p>
            </div>
          )}
        </div>
      )}
    </Card>
  );
};

export default SimpleTest;
