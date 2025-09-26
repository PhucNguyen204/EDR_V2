import React, { useState, useEffect } from 'react';
import { Card, Table, Tag, Badge, Button, Alert, Spin, Typography, Space, Row, Col, Statistic } from 'antd';
import { 
  SecurityScanOutlined, 
  ReloadOutlined, 
  InfoCircleOutlined,
  WarningOutlined,
  ExclamationCircleOutlined,
  CloseCircleOutlined
} from '@ant-design/icons';

const { Text, Title } = Typography;

const Rules = () => {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState(null);

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
      case 'critical': return <CloseCircleOutlined />;
      case 'high': return <ExclamationCircleOutlined />;
      case 'medium': return <WarningOutlined />;
      case 'low': return <InfoCircleOutlined />;
      default: return <InfoCircleOutlined />;
    }
  };

  const fetchRules = async () => {
    try {
      setLoading(true);
      // Fetch rules directly from database
      const response = await fetch('http://localhost:8080/api/v1/rules/list?limit=1000');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const rules = await response.json();
      
      setRules(Array.isArray(rules) ? rules : []);
      setError(null);
    } catch (err) {
      console.error("Failed to fetch rules:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/v1/stats');
      const data = await response.json();
      setStats(data);
    } catch (err) {
      console.error('Stats fetch error:', err);
    }
  };

  useEffect(() => {
    fetchRules();
    fetchStats();
  }, []);

  const columns = [
    {
      title: 'Rule Name',
      dataIndex: 'title',
      key: 'title',
      render: (text, record) => (
        <div>
          <Text strong>{text || record.rule_name || 'Unknown Rule'}</Text>
          {record.rule_uid && (
            <div>
              <Text type="secondary" style={{ fontSize: '12px' }}>
                UID: {record.rule_uid}
              </Text>
            </div>
          )}
        </div>
      ),
    },
    {
      title: 'Severity',
      dataIndex: 'level',
      key: 'level',
      render: (level) => (
        <Tag 
          color={getSeverityColor(level)} 
          icon={getSeverityIcon(level)}
        >
          {level?.toUpperCase() || 'UNKNOWN'}
        </Tag>
      ),
      filters: [
        { text: 'Critical', value: 'critical' },
        { text: 'High', value: 'high' },
        { text: 'Medium', value: 'medium' },
        { text: 'Low', value: 'low' },
      ],
      onFilter: (value, record) => record.level?.toLowerCase() === value,
    },
    {
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      render: (text) => (
        <Text type="secondary" style={{ fontSize: '12px' }}>
          {text || 'No description available'}
        </Text>
      ),
      ellipsis: true,
    },
    {
      title: 'Status',
      key: 'status',
      render: () => (
        <Badge status="processing" text="Active" />
      ),
    },
  ];

  return (
    <div>
      {/* Stats Row */}
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24} sm={8}>
          <Card size="small">
            <Statistic
              title="Total Rules"
              value={stats?.rule_count || 0}
              prefix={<SecurityScanOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card size="small">
            <Statistic
              title="Engine Nodes"
              value={stats?.node_count || 0}
              prefix={<InfoCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card size="small">
            <Statistic
              title="Correlation Windows"
              value={stats?.correlation_windows || 0}
              prefix={<WarningOutlined />}
              valueStyle={{ color: '#faad14' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Rules Table */}
      <Card
        title={
          <Space>
            <SecurityScanOutlined />
            Security Rules
            {rules.length > 0 && (
              <Badge count={rules.length} style={{ backgroundColor: '#1890ff' }} />
            )}
          </Space>
        }
        extra={
          <Button 
            icon={<ReloadOutlined />} 
            onClick={fetchRules}
            loading={loading}
            size="small"
          >
            Refresh
          </Button>
        }
      >
        {error && (
          <Alert
            message="Error Loading Rules"
            description={error}
            type="error"
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}

        {loading && rules.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px' }}>
            <Spin size="large" />
            <p>Loading rules...</p>
          </div>
        ) : rules.length === 0 ? (
          <Alert
            message="No rules found"
            description="No security rules loaded in the system."
            type="info"
            showIcon
          />
        ) : (
          <Table
            columns={columns}
            dataSource={Array.isArray(rules) ? rules : []}
            rowKey="rule_id"
            pagination={{
              pageSize: 20,
              showSizeChanger: true,
              showQuickJumper: true,
              showTotal: (total, range) => 
                `${range[0]}-${range[1]} of ${total} rules`,
            }}
            scroll={{ x: 800 }}
            size="small"
          />
        )}
      </Card>
    </div>
  );
};

export default Rules;