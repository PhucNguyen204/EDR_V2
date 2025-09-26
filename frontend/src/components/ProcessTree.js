import React, { useState } from 'react';
import { 
  Card, 
  Tree, 
  Select, 
  Button, 
  Space, 
  Tag, 
  Row, 
  Col,
  Alert,
  Spin,
  Modal,
  Descriptions
} from 'antd';
import { 
  ReloadOutlined, 
  EyeOutlined,
  WarningOutlined,
  CheckCircleOutlined 
} from '@ant-design/icons';
import { useQuery } from 'react-query';
import { processTreeAPI, endpointsAPI } from '../services/api';

const ProcessTree = () => {
  const [selectedEndpoint, setSelectedEndpoint] = useState('');
  const [selectedProcess, setSelectedProcess] = useState(null);

  const { data: endpoints } = useQuery('endpoints', endpointsAPI.getEndpoints);
  const { data: processTree, isLoading } = useQuery(
    ['processTree', selectedEndpoint],
    () => processTreeAPI.getProcessTree(selectedEndpoint),
    { enabled: !!selectedEndpoint }
  );
  const { data: suspiciousProcesses } = useQuery(
    ['suspiciousProcesses', selectedEndpoint],
    () => processTreeAPI.getSuspiciousProcesses(selectedEndpoint),
    { enabled: !!selectedEndpoint }
  );

  const buildTreeData = (processes) => {
    if (!processes || processes.length === 0) return [];

    const processMap = new Map();
    const rootProcesses = [];

    // Create process map
    processes.forEach(process => {
      processMap.set(process.pid, {
        ...process,
        key: process.pid,
        title: (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>{process.executable}</span>
            <Tag color={process.is_suspicious ? 'red' : 'green'}>
              {process.is_suspicious ? 'Suspicious' : 'Normal'}
            </Tag>
          </div>
        ),
        children: []
      });
    });

    // Build tree structure
    processes.forEach(process => {
      const node = processMap.get(process.pid);
      if (process.ppid && processMap.has(process.ppid)) {
        const parent = processMap.get(process.ppid);
        parent.children.push(node);
      } else {
        rootProcesses.push(node);
      }
    });

    return rootProcesses;
  };

  const getProcessIcon = (process) => {
    if (process.is_suspicious) {
      return <WarningOutlined style={{ color: '#ff4d4f' }} />;
    }
    return <CheckCircleOutlined style={{ color: '#52c41a' }} />;
  };

  const treeData = buildTreeData(processTree?.data?.processes || []);

  return (
    <div>
      <Card>
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col xs={24} sm={12}>
            <Select
              placeholder="Select endpoint"
              style={{ width: '100%' }}
              value={selectedEndpoint}
              onChange={setSelectedEndpoint}
            >
              {endpoints?.data?.map(endpoint => (
                <Select.Option key={endpoint.EndpointID} value={endpoint.EndpointID}>
                  {endpoint.HostName} ({endpoint.EndpointID.substring(0, 8)}...)
                </Select.Option>
              ))}
            </Select>
          </Col>
          <Col xs={24} sm={12}>
            <Space>
              <Button 
                icon={<ReloadOutlined />} 
                onClick={() => window.location.reload()}
              >
                Refresh
              </Button>
            </Space>
          </Col>
        </Row>

        {!selectedEndpoint ? (
          <Alert 
            message="Please select an endpoint to view the process tree" 
            type="info" 
          />
        ) : isLoading ? (
          <div style={{ textAlign: 'center', padding: '50px' }}>
            <Spin size="large" />
          </div>
        ) : (
          <Row gutter={[16, 16]}>
            <Col xs={24} lg={16}>
              <Card title="Process Tree" size="small">
                {treeData.length === 0 ? (
                  <Alert message="No processes found" type="info" />
                ) : (
                  <Tree
                    showIcon
                    defaultExpandAll
                    treeData={treeData}
                    onSelect={(selectedKeys, info) => {
                      if (info.node) {
                        setSelectedProcess(info.node);
                      }
                    }}
                  />
                )}
              </Card>
            </Col>
            
            <Col xs={24} lg={8}>
              <Card title="Suspicious Processes" size="small">
                {suspiciousProcesses?.data?.length === 0 ? (
                  <Alert message="No suspicious processes found" type="success" />
                ) : (
                  suspiciousProcesses?.data?.map(process => (
                    <div 
                      key={process.pid}
                      style={{ 
                        padding: '8px', 
                        border: '1px solid #ff4d4f', 
                        borderRadius: '4px', 
                        marginBottom: '8px',
                        cursor: 'pointer'
                      }}
                      onClick={() => setSelectedProcess(process)}
                    >
                      <div style={{ fontWeight: 'bold' }}>{process.executable}</div>
                      <div style={{ fontSize: '12px', color: '#666' }}>
                        PID: {process.pid} | PPID: {process.ppid}
                      </div>
                      <Tag color="red">Suspicious</Tag>
                    </div>
                  ))
                )}
              </Card>
            </Col>
          </Row>
        )}
      </Card>

      <Modal
        title="Process Details"
        open={!!selectedProcess}
        onCancel={() => setSelectedProcess(null)}
        footer={[
          <Button key="close" onClick={() => setSelectedProcess(null)}>
            Close
          </Button>
        ]}
        width={600}
      >
        {selectedProcess && (
          <Descriptions bordered column={1}>
            <Descriptions.Item label="Executable">
              {selectedProcess.executable}
            </Descriptions.Item>
            <Descriptions.Item label="PID">
              {selectedProcess.pid}
            </Descriptions.Item>
            <Descriptions.Item label="PPID">
              {selectedProcess.ppid}
            </Descriptions.Item>
            <Descriptions.Item label="Command Line">
              {selectedProcess.command_line || 'N/A'}
            </Descriptions.Item>
            <Descriptions.Item label="User">
              {selectedProcess.user || 'N/A'}
            </Descriptions.Item>
            <Descriptions.Item label="Status">
              <Tag color={selectedProcess.is_suspicious ? 'red' : 'green'}>
                {selectedProcess.is_suspicious ? 'Suspicious' : 'Normal'}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Created At">
              {selectedProcess.created_at ? new Date(selectedProcess.created_at).toLocaleString() : 'N/A'}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </div>
  );
};

export default ProcessTree;
