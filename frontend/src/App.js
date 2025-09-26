import React, { useState } from 'react';
import { Routes, Route } from 'react-router-dom';
import { Layout } from 'antd';
import Dashboard from './components/Dashboard';
import Alerts from './components/Alerts';
import ProcessTree from './components/ProcessTree';
import Rules from './components/Rules';
import Endpoints from './components/Endpoints';
import Navigation from './components/Navigation';

const { Content } = Layout;

function App() {
  const [alertCount, setAlertCount] = useState(0);

  const handleRefresh = () => {
    // Refresh logic can be implemented here
    window.location.reload();
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Navigation 
        alertCount={alertCount} 
        onRefresh={handleRefresh}
      />
      <Content style={{ padding: '24px', background: '#f0f2f5' }}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/process-tree" element={<ProcessTree />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/endpoints" element={<Endpoints />} />
        </Routes>
      </Content>
    </Layout>
  );
}

export default App;
