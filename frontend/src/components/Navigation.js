import React, { useState } from 'react';
import { Layout, Menu, Button, Badge, Space, Typography } from 'antd';
import { 
  DashboardOutlined, 
  AlertOutlined, 
  SettingOutlined,
  BarChartOutlined,
  SecurityScanOutlined,
  ReloadOutlined
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';

const { Header } = Layout;
const { Text } = Typography;

const Navigation = ({ alertCount = 0, onRefresh }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [selectedKey, setSelectedKey] = useState(location.pathname);

  const menuItems = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: 'Dashboard',
    },
    {
      key: '/alerts',
      icon: <AlertOutlined />,
      label: (
        <Space>
          <span>Alerts</span>
          {alertCount > 0 && (
            <Badge count={alertCount} size="small" />
          )}
        </Space>
      ),
    },
    {
      key: '/rules',
      icon: <SecurityScanOutlined />,
      label: 'Rules',
    },
    {
      key: '/analytics',
      icon: <BarChartOutlined />,
      label: 'Analytics',
    },
    {
      key: '/settings',
      icon: <SettingOutlined />,
      label: 'Settings',
    },
  ];

  const handleMenuClick = ({ key }) => {
    setSelectedKey(key);
    navigate(key);
  };

  return (
    <Header 
      style={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        padding: '0 24px',
        background: '#001529',
        boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
        position: 'sticky',
        top: 0,
        zIndex: 1000
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          marginRight: '24px',
          cursor: 'pointer'
        }} onClick={() => navigate('/')}>
          <SecurityScanOutlined style={{ fontSize: '24px', color: '#1890ff', marginRight: '8px' }} />
          <Text style={{ color: 'white', fontSize: '18px', fontWeight: 'bold' }}>
            EDR Security Dashboard
          </Text>
        </div>
        
        <Menu
          theme="dark"
          mode="horizontal"
          selectedKeys={[selectedKey]}
          items={menuItems}
          onClick={handleMenuClick}
          style={{ 
            flex: 1, 
            minWidth: 0,
            border: 'none',
            background: 'transparent'
          }}
        />
      </div>

      <Space>
        <Button 
          type="text" 
          icon={<ReloadOutlined />} 
          onClick={onRefresh}
          style={{ color: 'white' }}
        >
          Refresh
        </Button>
        <Badge 
          status="processing" 
          text={
            <Text style={{ color: 'white' }}>
              Real-time
            </Text>
          } 
        />
      </Space>
    </Header>
  );
};

export default Navigation;
