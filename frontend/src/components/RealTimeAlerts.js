import React, { useState, useEffect } from 'react';
import { Card, List, Tag, Badge, Button, Alert, Spin, Typography, Space, Row, Col } from 'antd';
import { 
  AlertOutlined, 
  ReloadOutlined, 
  ClockCircleOutlined,
  DesktopOutlined,
  SecurityScanOutlined
} from '@ant-design/icons';
import SeverityFilter from './SeverityFilter';

const { Text, Title } = Typography;

const RealTimeAlerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [viewedAlerts, setViewedAlerts] = useState(new Set());

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'high': return 'red';
      case 'medium': return 'orange';
      case 'low': return 'green';
      case 'critical': return 'purple';
      default: return 'blue';
    }
  };

  const getSeverityCounts = () => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach(alert => {
      const severity = alert.severity?.toLowerCase() || 'low';
      counts[severity] = (counts[severity] || 0) + 1;
    });
    return counts;
  };

  const getFilteredAlerts = () => {
    if (selectedSeverity === 'all') {
      return alerts;
    }
    return alerts.filter(alert => 
      alert.severity?.toLowerCase() === selectedSeverity
    );
  };

  const fetchLatestAlerts = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:8080/api/v1/detections?limit=50');
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      
      // Ensure data is an array
      if (Array.isArray(data)) {
        // Merge with existing alerts to prevent data loss
        setAlerts(prevAlerts => {
          // Create a map of existing alerts by ID for quick lookup
          const existingMap = new Map();
          prevAlerts.forEach(alert => {
            if (alert.id) {
              existingMap.set(alert.id, alert);
            }
          });
          
          // Merge new data with existing, keeping existing alerts that aren't in new data
          const mergedAlerts = [...data];
          
          // Add any existing alerts that aren't in the new data (to prevent disappearing)
          prevAlerts.forEach(alert => {
            if (alert.id && !data.find(newAlert => newAlert.id === alert.id)) {
              // Keep alerts that have been viewed or are from last 30 minutes
              const alertTime = new Date(alert.occurred_at);
              const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
              const isViewed = viewedAlerts.has(alert.id);
              const isRecent = alertTime > thirtyMinutesAgo;
              
              if (isViewed || isRecent) {
                mergedAlerts.push(alert);
              }
            }
          });
          
          // Sort by occurred_at descending
          return mergedAlerts.sort((a, b) => new Date(b.occurred_at) - new Date(a.occurred_at));
        });
        
        setIsConnected(true);
        setError(null);
      } else {
        console.error('Invalid data format:', data);
        setError('Invalid data format received from server');
      }
    } catch (err) {
      console.error('Fetch error:', err);
      setError(err.message);
      setIsConnected(false);
    } finally {
      setLoading(false);
    }
  };

  const startRealTimeUpdates = () => {
    // Polling every 10 seconds for real-time updates (reduced frequency)
    const interval = setInterval(() => {
      // Only fetch if not currently loading to prevent race conditions
      if (!loading) {
        fetchLatestAlerts();
      }
    }, 10000);
    return () => clearInterval(interval);
  };

  useEffect(() => {
    fetchLatestAlerts();
    const cleanup = startRealTimeUpdates();
    return cleanup;
  }, []);

  const formatTime = (timeString) => {
    return new Date(timeString).toLocaleString('vi-VN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const getEventSummary = (context) => {
    if (!context) return 'No event details';
    
    const summary = [];
    if (context.User) summary.push(`User: ${context.User}`);
    if (context.Image) summary.push(`Process: ${context.Image.split('\\').pop()}`);
    if (context.CommandLine) summary.push(`Command: ${context.CommandLine.substring(0, 50)}...`);
    if (context.Computer) summary.push(`Computer: ${context.Computer}`);
    
    return summary.length > 0 ? summary.join(' | ') : 'Event details available';
  };

  const markAlertAsViewed = (alertId) => {
    setViewedAlerts(prev => new Set([...prev, alertId]));
  };

  const severityCounts = getSeverityCounts();
  const filteredAlerts = getFilteredAlerts();

  return (
    <div>
      <Row gutter={[16, 16]}>
        <Col xs={24}>
          <SeverityFilter
            selectedSeverity={selectedSeverity}
            onSeverityChange={setSelectedSeverity}
            severityCounts={severityCounts}
            totalAlerts={alerts.length}
          />
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24}>
          <Card
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Badge 
                  status={isConnected ? 'success' : 'error'} 
                  text={
                    <Space>
                      <AlertOutlined />
                      Real-Time Security Alerts
                      {filteredAlerts.length > 0 && (
                        <Tag color="blue">{filteredAlerts.length} alerts</Tag>
                      )}
                    </Space>
                  }
                />
              </div>
            }
            extra={
              <Space>
                <Button 
                  icon={<ReloadOutlined />} 
                  onClick={fetchLatestAlerts}
                  loading={loading}
                  size="small"
                >
                  Refresh
                </Button>
                {viewedAlerts.size > 0 && (
                  <Button 
                    onClick={() => setViewedAlerts(new Set())}
                    size="small"
                    type="text"
                  >
                    Clear Viewed ({viewedAlerts.size})
                  </Button>
                )}
              </Space>
            }
          >
      {error && (
        <Alert
          message="Connection Error"
          description={error}
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
        />
      )}

            {loading && alerts.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '20px' }}>
                <Spin size="large" />
                <p>Loading alerts...</p>
              </div>
            ) : filteredAlerts.length === 0 ? (
              <Alert
                message="No alerts found"
                description={`No ${selectedSeverity === 'all' ? '' : selectedSeverity + ' '}security alerts detected in the system.`}
                type="info"
                showIcon
              />
            ) : (
              <List
                dataSource={Array.isArray(filteredAlerts) ? filteredAlerts : []}
          renderItem={(alert, index) => (
            <List.Item
              key={alert.id || index}
              onClick={() => markAlertAsViewed(alert.id)}
              style={{
                border: `1px solid ${viewedAlerts.has(alert.id) ? '#d9d9d9' : '#f0f0f0'}`,
                borderRadius: '6px',
                marginBottom: '8px',
                padding: '12px',
                backgroundColor: index < 3 ? '#fff7e6' : (viewedAlerts.has(alert.id) ? '#fafafa' : '#fff'),
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                opacity: viewedAlerts.has(alert.id) ? 0.8 : 1
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = '#f5f5f5';
                e.currentTarget.style.transform = 'translateY(-1px)';
                e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = index < 3 ? '#fff7e6' : '#fff';
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <List.Item.Meta
                avatar={
                  <div style={{ textAlign: 'center' }}>
                    <SecurityScanOutlined 
                      style={{ 
                        fontSize: '24px', 
                        color: getSeverityColor(alert.severity) === 'red' ? '#ff4d4f' : 
                               getSeverityColor(alert.severity) === 'orange' ? '#faad14' : '#52c41a'
                      }} 
                    />
                    <div style={{ fontSize: '10px', marginTop: '4px' }}>
                      #{alert.id}
                    </div>
                  </div>
                }
                title={
                  <div>
                    <Space>
                      <Title level={5} style={{ margin: 0 }}>
                        {alert.rule_name || alert.rule_title || 'Unknown Rule'}
                      </Title>
                      <Tag color={getSeverityColor(alert.severity)}>
                        {alert.severity?.toUpperCase() || 'UNKNOWN'}
                      </Tag>
                    </Space>
                  </div>
                }
                description={
                  <div>
                    <Space direction="vertical" size="small" style={{ width: '100%' }}>
                      <div>
                        <Space>
                          <DesktopOutlined />
                          <Text code>{alert.endpoint_id?.substring(0, 8)}...</Text>
                          <ClockCircleOutlined />
                          <Text type="secondary">{formatTime(alert.occurred_at)}</Text>
                        </Space>
                      </div>
                      
                      <div>
                        <Text type="secondary">
                          {getEventSummary(alert.context)}
                        </Text>
                      </div>
                      
                      {alert.rule_description && (
                        <div>
                          <Text type="secondary" style={{ fontSize: '12px' }}>
                            {alert.rule_description}
                          </Text>
                        </div>
                      )}
                    </Space>
                  </div>
                }
              />
            </List.Item>
          )}
        />
      )}
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default RealTimeAlerts;
