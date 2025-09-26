import React from 'react';
import { 
  Card, 
  Table, 
  Tag, 
  Space, 
  Button, 
  Row, 
  Col,
  Statistic,
  Alert,
  Spin
} from 'antd';
import { 
  ReloadOutlined, 
  EyeOutlined,
  DesktopOutlined,
  ClockCircleOutlined 
} from '@ant-design/icons';
import { useQuery } from 'react-query';
import { endpointsAPI } from '../services/api';

const Endpoints = () => {
  const { data: endpoints, isLoading, refetch } = useQuery(
    'endpoints',
    endpointsAPI.getEndpoints,
    { refetchInterval: 10000 }
  );

  const getStatusColor = (lastSeen) => {
    const now = new Date();
    const lastSeenDate = new Date(lastSeen);
    const diffMinutes = (now - lastSeenDate) / (1000 * 60);
    
    if (diffMinutes < 5) return 'green';
    if (diffMinutes < 30) return 'orange';
    return 'red';
  };

  const getStatusText = (lastSeen) => {
    const now = new Date();
    const lastSeenDate = new Date(lastSeen);
    const diffMinutes = (now - lastSeenDate) / (1000 * 60);
    
    if (diffMinutes < 5) return 'Online';
    if (diffMinutes < 30) return 'Warning';
    return 'Offline';
  };

  const columns = [
    {
      title: 'Endpoint ID',
      dataIndex: 'EndpointID',
      key: 'EndpointID',
      render: (text) => (
        <span style={{ fontFamily: 'monospace', fontSize: '12px' }}>
          {text ? text.substring(0, 8) + '...' : 'Unknown'}
        </span>
      ),
    },
    {
      title: 'Host Name',
      dataIndex: 'HostName',
      key: 'HostName',
    },
    {
      title: 'IP Address',
      dataIndex: 'IP',
      key: 'IP',
    },
    {
      title: 'Agent Version',
      dataIndex: 'AgentVersion',
      key: 'AgentVersion',
      render: (text) => text || 'Unknown',
    },
    {
      title: 'Status',
      dataIndex: 'LastSeen',
      key: 'status',
      render: (lastSeen) => {
        const status = getStatusText(lastSeen);
        const color = getStatusColor(lastSeen);
        return <Tag color={color}>{status}</Tag>;
      },
      sorter: (a, b) => new Date(a.LastSeen) - new Date(b.LastSeen),
    },
    {
      title: 'Last Seen',
      dataIndex: 'LastSeen',
      key: 'LastSeen',
      render: (text) => new Date(text).toLocaleString(),
      sorter: (a, b) => new Date(a.LastSeen) - new Date(b.LastSeen),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Button 
            icon={<EyeOutlined />} 
            size="small"
            onClick={() => message.info('View details functionality not implemented')}
          >
            View
          </Button>
        </Space>
      ),
    },
  ];

  const endpointData = endpoints?.data || [];
  const onlineEndpoints = endpointData.filter(endpoint => {
    const lastSeen = new Date(endpoint.LastSeen);
    const now = new Date();
    const diffMinutes = (now - lastSeen) / (1000 * 60);
    return diffMinutes < 5;
  }).length;

  const offlineEndpoints = endpointData.filter(endpoint => {
    const lastSeen = new Date(endpoint.LastSeen);
    const now = new Date();
    const diffMinutes = (now - lastSeen) / (1000 * 60);
    return diffMinutes >= 30;
  }).length;

  return (
    <div>
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={8}>
          <Card>
            <Statistic
              title="Total Endpoints"
              value={endpointData.length}
              prefix={<DesktopOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card>
            <Statistic
              title="Online"
              value={onlineEndpoints}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card>
            <Statistic
              title="Offline"
              value={offlineEndpoints}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
      </Row>

      <Card>
        <div style={{ marginBottom: 16 }}>
          <Space>
            <Button 
              icon={<ReloadOutlined />}
              onClick={() => refetch()}
            >
              Refresh
            </Button>
          </Space>
        </div>

        {isLoading ? (
          <div style={{ textAlign: 'center', padding: '50px' }}>
            <Spin size="large" />
          </div>
        ) : endpointData.length === 0 ? (
          <Alert message="No endpoints found" type="info" />
        ) : (
          <Table
            columns={columns}
            dataSource={endpointData}
            rowKey="EndpointID"
            pagination={{
              pageSize: 20,
              showSizeChanger: true,
              showQuickJumper: true,
              showTotal: (total) => `Total ${total} endpoints`,
            }}
            scroll={{ x: 800 }}
          />
        )}
      </Card>
    </div>
  );
};

export default Endpoints;
