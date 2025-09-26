import React, { useState, useEffect } from 'react';
import { Card, Row, Col, Statistic, Badge, Typography, Space } from 'antd';
import { 
  AlertOutlined, 
  SecurityScanOutlined, 
  DesktopOutlined,
  NodeIndexOutlined,
  ClockCircleOutlined
} from '@ant-design/icons';

const { Text } = Typography;

const RealTimeStats = () => {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(null);

  const fetchStats = async () => {
    try {
      setLoading(true);
      
      // Fetch stats
      const statsResponse = await fetch('http://localhost:8080/api/v1/stats');
      const statsData = await statsResponse.json();
      setStats(statsData);
      
      // Fetch latest alerts for count
      const alertsResponse = await fetch('http://localhost:8080/api/v1/detections?limit=100');
      const alertsData = await alertsResponse.json();
      setAlerts(alertsData);
      
      setLastUpdate(new Date());
    } catch (err) {
      console.error('Stats fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    // Update every 10 seconds
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityCounts = () => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach(alert => {
      const severity = alert.severity?.toLowerCase() || 'low';
      if (counts.hasOwnProperty(severity)) {
        counts[severity] = (counts[severity] || 0) + 1;
      }
    });
    return counts;
  };

  const severityCounts = getSeverityCounts();

  return (
    <Card
      title={
        <Space>
          <Badge status="processing" />
          <span>Real-Time Security Statistics</span>
          {lastUpdate && (
            <Text type="secondary" style={{ fontSize: '12px' }}>
              Last updated: {lastUpdate.toLocaleTimeString()}
            </Text>
          )}
        </Space>
      }
      loading={loading}
    >
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card size="small">
            <Statistic
              title="Total Rules"
              value={stats?.rule_count || 0}
              prefix={<SecurityScanOutlined />}
              valueStyle={{ color: '#1890ff', fontSize: '20px' }}
            />
          </Card>
        </Col>
        
        <Col xs={24} sm={12} lg={6}>
          <Card size="small">
            <Statistic
              title="Engine Nodes"
              value={stats?.node_count || 0}
              prefix={<NodeIndexOutlined />}
              valueStyle={{ color: '#52c41a', fontSize: '20px' }}
            />
          </Card>
        </Col>
        
        <Col xs={24} sm={12} lg={6}>
          <Card size="small">
            <Statistic
              title="Total Alerts"
              value={alerts.length}
              prefix={<AlertOutlined />}
              valueStyle={{ color: '#faad14', fontSize: '20px' }}
            />
          </Card>
        </Col>
        
        <Col xs={24} sm={12} lg={6}>
          <Card size="small">
            <Statistic
              title="Correlation Windows"
              value={stats?.correlation_windows || 0}
              prefix={<ClockCircleOutlined />}
              valueStyle={{ color: '#722ed1', fontSize: '20px' }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} sm={6}>
          <Card size="small">
            <Statistic
              title="Critical"
              value={severityCounts.critical}
              valueStyle={{ color: '#722ed1', fontSize: '18px' }}
            />
          </Card>
        </Col>
        
        <Col xs={24} sm={6}>
          <Card size="small">
            <Statistic
              title="High Severity"
              value={severityCounts.high}
              valueStyle={{ color: '#ff4d4f', fontSize: '18px' }}
            />
          </Card>
        </Col>
        
        <Col xs={24} sm={6}>
          <Card size="small">
            <Statistic
              title="Medium Severity"
              value={severityCounts.medium}
              valueStyle={{ color: '#faad14', fontSize: '18px' }}
            />
          </Card>
        </Col>
        
        <Col xs={24} sm={6}>
          <Card size="small">
            <Statistic
              title="Low Severity"
              value={severityCounts.low}
              valueStyle={{ color: '#52c41a', fontSize: '18px' }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24}>
          <Card size="small">
            <Row gutter={[16, 16]}>
              <Col span={12}>
                <Statistic
                  title="Nodes Evaluated"
                  value={stats?.nodes_evaluated || 0}
                  valueStyle={{ fontSize: '16px' }}
                />
              </Col>
              <Col span={12}>
                <Statistic
                  title="Primitive Evaluations"
                  value={stats?.primitive_evaluations || 0}
                  valueStyle={{ fontSize: '16px' }}
                />
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>
    </Card>
  );
};

export default RealTimeStats;
