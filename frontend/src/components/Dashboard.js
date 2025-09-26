import React from 'react';
import { Card, Row, Col, Statistic, Alert, Spin } from 'antd';
import { 
  AlertOutlined, 
  SecurityScanOutlined, 
  NodeIndexOutlined,
  DesktopOutlined 
} from '@ant-design/icons';
import { useQuery } from 'react-query';
import { statsAPI, endpointsAPI } from '../services/api';
import Alerts from './Alerts';
import SimpleTest from './SimpleTest';
import Rules from './Rules';
import RealTimeAlerts from './RealTimeAlerts';
import RealTimeStats from './RealTimeStats';
import EventStream from './EventStream';
import ErrorBoundary from './ErrorBoundary';

const Dashboard = () => {
  const { data: stats, isLoading: statsLoading } = useQuery(
    'stats',
    statsAPI.getStats,
    { refetchInterval: 5000 }
  );

  // Removed alerts query - now handled by Alerts component

  const { data: endpoints, isLoading: endpointsLoading } = useQuery(
    'endpoints',
    endpointsAPI.getEndpoints,
    { refetchInterval: 10000 }
  );

  if (statsLoading || endpointsLoading) {
    return (
      <div style={{ textAlign: 'center', padding: '50px' }}>
        <Spin size="large" />
      </div>
    );
  }

  // Get high severity count from stats if available
  const highSeverityAlerts = stats?.high_severity_alerts || 0;

  return (
    <div>
      <h1>Security Dashboard</h1>
      
      {/* Statistics Cards */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Total Rules"
              value={stats?.rule_count || 0}
              prefix={<SecurityScanOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Active Endpoints"
              value={endpoints?.length || 0}
              prefix={<DesktopOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Total Detections"
              value={stats?.total_detections || 0}
              prefix={<AlertOutlined />}
              valueStyle={{ color: '#faad14' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Engine Nodes"
              value={stats?.node_count || 0}
              prefix={<NodeIndexOutlined />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Real-Time Stats */}
      <Row gutter={[16, 16]}>
        <Col xs={24}>
          <ErrorBoundary>
            <RealTimeStats />
          </ErrorBoundary>
        </Col>
      </Row>


      {/* Event Stream */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24}>
          <ErrorBoundary>
            <EventStream />
          </ErrorBoundary>
        </Col>
      </Row>

      {/* Rules Table */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24}>
          <ErrorBoundary>
            <Rules />
          </ErrorBoundary>
        </Col>
      </Row>

      {/* Alerts Table */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24}>
          <ErrorBoundary>
            <Alerts />
          </ErrorBoundary>
        </Col>
      </Row>

      {/* System Status */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24}>
          <Card title="System Status">
            <Row gutter={[16, 16]}>
              <Col span={12}>
                <Statistic
                  title="Engine Nodes"
                  value={stats?.node_count || 0}
                  valueStyle={{ fontSize: 16 }}
                />
              </Col>
              <Col span={12}>
                <Statistic
                  title="Correlation Windows"
                  value={stats?.correlation_windows || 0}
                  valueStyle={{ fontSize: 16 }}
                />
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;
