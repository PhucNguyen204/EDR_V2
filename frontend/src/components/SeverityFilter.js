import React from 'react';
import { Card, Row, Col, Button, Badge, Typography, Space, Statistic } from 'antd';
import { 
  AlertOutlined, 
  ExclamationCircleOutlined,
  InfoCircleOutlined,
  WarningOutlined,
  CloseCircleOutlined
} from '@ant-design/icons';

const { Text, Title } = Typography;

const SeverityFilter = ({ 
  selectedSeverity, 
  onSeverityChange, 
  severityCounts = {},
  totalAlerts = 0 
}) => {
  const severityOptions = [
    {
      key: 'all',
      label: 'All Alerts',
      icon: <AlertOutlined />,
      color: '#1890ff',
      count: totalAlerts
    },
    {
      key: 'critical',
      label: 'Critical',
      icon: <CloseCircleOutlined />,
      color: '#722ed1',
      count: severityCounts.critical || 0
    },
    {
      key: 'high',
      label: 'High',
      icon: <ExclamationCircleOutlined />,
      color: '#ff4d4f',
      count: severityCounts.high || 0
    },
    {
      key: 'medium',
      label: 'Medium',
      icon: <WarningOutlined />,
      color: '#faad14',
      count: severityCounts.medium || 0
    },
    {
      key: 'low',
      label: 'Low',
      icon: <InfoCircleOutlined />,
      color: '#52c41a',
      count: severityCounts.low || 0
    }
  ];

  return (
    <Card 
      title={
        <Space>
          <AlertOutlined />
          <span>Filter by Severity</span>
          <Badge count={totalAlerts} style={{ backgroundColor: '#1890ff' }} />
        </Space>
      }
      size="small"
    >
      <Row gutter={[8, 8]}>
        {severityOptions.map((option) => (
          <Col key={option.key} xs={24} sm={12} lg={8} xl={4}>
            <Button
              type={selectedSeverity === option.key ? 'primary' : 'default'}
              size="small"
              block
              onClick={() => onSeverityChange(option.key)}
              style={{
                borderColor: option.color,
                color: selectedSeverity === option.key ? 'white' : option.color,
                backgroundColor: selectedSeverity === option.key ? option.color : 'transparent',
                height: '60px',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: '4px' }}>
                {option.icon}
                <Text 
                  style={{ 
                    marginLeft: '4px', 
                    fontSize: '12px',
                    color: selectedSeverity === option.key ? 'white' : option.color,
                    fontWeight: 'bold'
                  }}
                >
                  {option.label}
                </Text>
              </div>
              <Badge 
                count={option.count} 
                style={{ 
                  backgroundColor: selectedSeverity === option.key ? 'rgba(255,255,255,0.3)' : option.color,
                  color: selectedSeverity === option.key ? 'white' : 'white',
                  fontSize: '10px',
                  minWidth: '20px',
                  height: '16px',
                  lineHeight: '16px'
                }}
              />
            </Button>
          </Col>
        ))}
      </Row>
      
      <div style={{ marginTop: '12px', textAlign: 'center' }}>
        <Text type="secondary" style={{ fontSize: '12px' }}>
          Showing {selectedSeverity === 'all' ? totalAlerts : severityCounts[selectedSeverity] || 0} alerts
        </Text>
      </div>
    </Card>
  );
};

export default SeverityFilter;
