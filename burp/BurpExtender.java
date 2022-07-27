package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter debug;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.callbacks.setExtensionName("sample extension");

        this.callbacks.registerHttpListener(this);

        this.debug = new PrintWriter(callbacks.getStdout(), true);
        //this.debug.println("hello");
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        // only process responses
        if (!messageIsRequest) {
            // create a new log entry with the message details
            synchronized (log) {
                int row = log.size();
                log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                        helpers.analyzeRequest(messageInfo).getUrl()));
                fireTableRowsInserted(row, row);
            }
        }
    }

    //
    // extend AbstractTableModel
    //

    @Override
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 1;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "API Routes";
//            case 1:
//                return "URL";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return logEntry.url.getPath(); //callbacks.getToolName(logEntry.tool);
            case 1:
                return logEntry.url.toString();
            default:
                return "";

            if (messageIsRequest) {
                this.debug.println("Intercepted Request!");
            } else {
                this.debug.println("You entered incorrect input");

            }
        }
    }
}
