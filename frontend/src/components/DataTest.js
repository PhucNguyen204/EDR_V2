import React, { useState, useEffect } from 'react';
import { Card, Button, Alert, Table, Tag, Spin } from 'antd';
import { ReloadOutlined, DatabaseOutlined } from '@ant-design/icons';

const DataTest = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    
    try {
      console.log('Fetching data...');
      
      // Test Stats API
      const statsResponse = await fetch('http://localhost:8080/api/v1/stats');
      const statsData = await statsResponse.json();
      console.log('Stats API Response:', statsData);
      
      // Test Alerts API
      const alertsResponse = await fetch('http://localhost:8080/api/v1/detections?limit=10');
      const alertsData = await alertsResponse.json();
      console.log('Alerts API Response:', alertsData);
      
      setData({
        stats: statsData,
        alerts: alertsData
      });
      
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

  const columns = [
    {
      title: 'Rule Name',
      dataIndex: 'rule_name',
      key: 'rule_name',
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      render: (severity) => (
        <Tag color={severity === 'high' ? 'red' : severity === 'medium' ? 'orange' : 'green'}>
          {severity?.toUpperCase()}
        </Tag>
      ),
    },
    {
      title: 'Time',
      dataIndex: 'occurred_at',
      key: 'occurred_at',
      render: (time) => new Date(time).toLocaleString(),
    },
  ];

  return (
    <Card
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <DatabaseOutlined />
          Database Data Test
        </div>
      }
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
      
      {data && (
        <div>
          <div style={{ marginBottom: 16 }}>
            <h3>Stats API Result:</h3>
            <p>✅ Rules: {data.stats.rule_count}</p>
            <p>✅ Nodes: {data.stats.node_count}</p>
            <p>✅ Correlation Windows: {data.stats.correlation_windows}</p>
          </div>
          
          <div>
            <h3>Alerts API Result:</h3>
            <p>✅ Found {data.alerts.length} detections</p>
            
            <Table
              columns={columns}
              dataSource={data.alerts}
              rowKey="id"
              size="small"
              pagination={{ pageSize: 5 }}
            />
          </div>
        </div>
      )}
    </Card>
  );
};

export default DataTest;
