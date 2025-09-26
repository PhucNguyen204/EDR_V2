import React, { useState, useEffect } from 'react';
import { Card, Button, Timeline, Tag, Typography, Space, Alert, Spin } from 'antd';
import { 
  PlayCircleOutlined, 
  PauseCircleOutlined, 
  ReloadOutlined,
  DesktopOutlined,
  ClockCircleOutlined,
  SecurityScanOutlined
} from '@ant-design/icons';

const { Text, Title } = Typography;

const EventStream = () => {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState(null);

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'purple';
      case 'high': return 'red';
      case 'medium': return 'orange';
      case 'low': return 'green';
      default: return 'blue';
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return '🔴';
      case 'high': return '🟠';
      case 'medium': return '🟡';
      case 'low': return '🟢';
      default: return '🔵';
    }
  };

  const formatTime = (timestamp) => {
    if (!timestamp) return 'Unknown';
    try {
      return new Date(timestamp).toLocaleTimeString();
    } catch {
      return 'Invalid time';
    }
  };

  const getEventDescription = (event) => {
    if (event.context) {
      if (typeof event.context === 'string') {
        return event.context;
      }
      if (event.context.CommandLine) {
        return `Command: ${event.context.CommandLine}`;
      }
      if (event.context.Image) {
        return `Process: ${event.context.Image}`;
      }
      return JSON.stringify(event.context);
    }
    return 'Security event detected';
  };

  const fetchEvents = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('http://localhost:8080/api/v1/detections?limit=50');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setEvents(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error("Failed to fetch events:", e);
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const startStream = () => {
    setStreaming(true);
    fetchEvents();
    const interval = setInterval(fetchEvents, 3000);
    return () => clearInterval(interval);
  };

  const stopStream = () => {
    setStreaming(false);
  };

  useEffect(() => {
    if (streaming) {
      const cleanup = startStream();
      return cleanup;
    }
  }, [streaming]);

  return (
    <Card
      title={
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <SecurityScanOutlined />
            <span>Real-Time Event Stream</span>
            {streaming && <Tag color="green">LIVE</Tag>}
          </div>
          <Space>
            <Button
              type={streaming ? "default" : "primary"}
              icon={streaming ? <PauseCircleOutlined /> : <PlayCircleOutlined />}
              onClick={streaming ? stopStream : startStream}
              loading={loading}
            >
              {streaming ? 'Stop Stream' : 'Start Stream'}
            </Button>
            <Button
              icon={<ReloadOutlined />}
              onClick={fetchEvents}
              loading={loading}
            >
              Refresh
            </Button>
          </Space>
        </div>
      }
      style={{ height: '100%' }}
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

      {loading && (
        <div style={{ textAlign: 'center', padding: '40px' }}>
          <Spin size="large" />
          <div style={{ marginTop: '16px' }}>
            <Text type="secondary">Loading events...</Text>
          </div>
        </div>
      )}

      {!loading && (!events || events.length === 0) ? (
        <div style={{ textAlign: 'center', padding: '40px', color: '#999' }}>
          <SecurityScanOutlined style={{ fontSize: '48px', color: '#d9d9d9' }} />
          <p>No events to display</p>
          <Text type="secondary">Click "Start Stream" to begin monitoring</Text>
        </div>
      ) : (
        <Timeline
          mode="left"
          items={Array.isArray(events) ? events.slice(0, 20).map((event, index) => ({
            color: getSeverityColor(event.severity),
            children: (
              <div style={{ 
                padding: '8px 12px', 
                backgroundColor: index < 3 ? '#fff7e6' : '#fafafa',
                borderRadius: '6px',
                border: '1px solid #f0f0f0'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ marginRight: '8px', fontSize: '16px' }}>
                    {getSeverityIcon(event.severity)}
                  </span>
                  <Title level={5} style={{ margin: 0, flex: 1 }}>
                    {event.rule_name || event.rule_title || 'Unknown Rule'}
                  </Title>
                  <Tag color={getSeverityColor(event.severity)} size="small">
                    {event.severity?.toUpperCase() || 'UNKNOWN'}
                  </Tag>
                </div>
                
                <div style={{ marginBottom: '4px' }}>
                  <Space>
                    <DesktopOutlined />
                    <Text code style={{ fontSize: '12px' }}>
                      {event.endpoint_id?.substring(0, 8)}...
                    </Text>
                    <ClockCircleOutlined />
                    <Text type="secondary" style={{ fontSize: '12px' }}>
                      {formatTime(event.occurred_at)}
                    </Text>
                  </Space>
                </div>
                
                <div>
                  <Text type="secondary" style={{ fontSize: '12px' }}>
                    {getEventDescription(event)}
                  </Text>
                </div>
                
                {event.rule_description && (
                  <div style={{ marginTop: '4px' }}>
                    <Text type="secondary" style={{ fontSize: '11px' }}>
                      {event.rule_description}
                    </Text>
                  </div>
                )}
              </div>
            )
          })) : []}
        />
      )}
    </Card>
  );
};

export default EventStream;