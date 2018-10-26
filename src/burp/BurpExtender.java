package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

public class BurpExtender implements IBurpExtender, IProxyListener, ITab {
	
	private JPanel panel;
	private JTable filterTable;
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName("Request Filter");
		callbacks.registerProxyListener(this);
		
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				panel = new JPanel(new BorderLayout());
				
				HostTableModel tableModel = new HostTableModel();
				filterTable = new JTable(tableModel);
				
				JScrollPane scrollPane = new JScrollPane(filterTable);
				JPanel west = new JPanel();
				west.setLayout(new BoxLayout(west, BoxLayout.Y_AXIS));
				JButton add = new JButton("Add");
				JButton edit = new JButton("Edit");
				JButton remove = new JButton("Remove");
				
				add.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent ae) {
						String hostName = JOptionPane.showInputDialog("Enter a host");
						if (!hostName.isEmpty()) {
							tableModel.addRow(hostName);
						}
					}
				});
				
				edit.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent ae) {
						int selected = filterTable.getSelectedRow();
						String hostName = JOptionPane.showInputDialog("Enter a host", filterTable.getModel().getValueAt(selected, 1));
						if (!hostName.isEmpty()) {
							tableModel.setValueAt(hostName, selected, 1);
						}
					}
				});
				
				remove.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent ae) {
						int selected = filterTable.getSelectedRow();
						tableModel.removeRow(selected);
					}
				});
				
				west.add(add);
				west.add(edit);
				west.add(remove);
				panel.add(west, BorderLayout.WEST);
				panel.add(scrollPane, BorderLayout.CENTER);
				
				callbacks.customizeUiComponent(panel);
				
				callbacks.addSuiteTab(BurpExtender.this);
			}
		});
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		if (messageIsRequest) {
			IHttpService httpService = message.getMessageInfo().getHttpService();
			HostTableModel table = (HostTableModel) filterTable.getModel();
			if (table.getHosts().parallelStream()
					.filter(host -> httpService.getHost().toLowerCase().contains(((String)host.getValueAt(1)).toLowerCase())
							&& (Boolean)host.getValueAt(0))
					.findFirst()
					.isPresent()) {
				message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
			}
		}
	}

	@Override
	public String getTabCaption() {
		return "Request Filter";
	}

	@Override
	public Component getUiComponent() {
		return panel;
	}
	
	class Host {
		
		private Object[] host;
		
		public Host(String hostName) {
			host = new Object[2];
			host[0] = Boolean.TRUE;
			host[1] = hostName;
		}
		
		public Object getValueAt(int index) {
			return host[index];
		}
		
		public void setData(int index, Object data) {
			host[index] = data;
		}
	}
	
	class HostTableModel extends AbstractTableModel {
		
		private String[] columnNames = {"Enabled", "Host"};
		private ArrayList<Host> HOSTS_FROM;
		
		public HostTableModel() {
			HOSTS_FROM = new ArrayList<Host>();
		}
		
		@Override
		public int getColumnCount() {
			return columnNames.length;
		}
		
		@Override
		public String getColumnName(int col) {
			return columnNames[col];
		}

		@Override
		public int getRowCount() {
			return HOSTS_FROM.size();
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			Host host = HOSTS_FROM.get(rowIndex);
			return host.getValueAt(columnIndex);
		}
		
		@Override
		public Class<?> getColumnClass(int columnIndex) {
			if (columnIndex == 0) {
				return Boolean.class;
			} else {
				return String.class;
			}
		}
		
		public void addRow(String host) {
			int rowCount = getRowCount();
			HOSTS_FROM.add(new Host(host));
			fireTableRowsInserted(rowCount, rowCount);
		}
		
		public void removeRow(int index) {
			HOSTS_FROM.remove(index);
			fireTableDataChanged();
		}
		
		@Override
		public boolean isCellEditable(int row, int col) {
			if (col == 0) {
				return true;
			} else {
				return false;
			}
		}
		
		@Override
		public void setValueAt(Object value, int row, int col) {
			HOSTS_FROM.get(row).setData(col, value);
			fireTableCellUpdated(row, col);
		}
		
		public ArrayList<Host> getHosts() {
			return HOSTS_FROM;
		}
	}
	

}
