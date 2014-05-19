

import java.io.Closeable;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

/**
 *
 * @author ctacon
 */
public class ScriptExecutor {

    private Logger logger;
    private DataSource dataSource;

    public ScriptExecutor(Logger logger, DataSource dataSource) {
	this.logger = logger;
	this.dataSource = dataSource;
    }

    public <T> List<T> executeRS(InputStream io, Map<Integer, Object> params, Convertor convertor) {
	Connection conn = null;
	PreparedStatement stmt = null;
	try {
	    Pattern multilinePattern = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
	    Pattern singlelinePattern = Pattern.compile("--.*");
	    String sqlScript = singlelinePattern.matcher(
		    multilinePattern.matcher(IOUtils.toString(io)).replaceAll("")).replaceAll("");
	    logger.debug("Выполняю скрипт = " + sqlScript);
	    conn = getConnection();
	    stmt = conn.prepareStatement(sqlScript);

	    for (Integer index : params.keySet()) {
		stmt.setObject(index, params.get(index));
	    }
	    ResultSet rs = stmt.executeQuery();
	    List<T> rows = new LinkedList<T>();
	    while (rs.next()) {
		Map<String, Object> row = new HashMap<String, Object>();
		for (int i = 1; i < rs.getMetaData().getColumnCount() + 1; i++) {
		    row.put(rs.getMetaData().getColumnName(i), rs.getObject(rs.getMetaData().getColumnName(i)));
		}
		rows.add((T) convertor.convert(row));
	    }
	    return rows;
	} catch (Exception ex) {
	    logger.error(ex, ex);
	    return null;
	} finally {
	    close(io);
	    JdbcUtil.close(stmt);
	    JdbcUtil.close(conn);
	}
    }

    private Connection getConnection() {
	try {
	    Connection connection = dataSource.getConnection();
	    connection.setAutoCommit(false);
	    return connection;
	} catch (Exception ex) {
	    logger.error(ex, ex);
	    return null;
	}
    }

    private void close(Object o) {
	try {
	    if (o != null && o instanceof Closeable) {
		((Closeable) o).close();
	    }
	} catch (Exception ex) {
	    logger.error(ex, ex);
	}
    }

abstract class Convertor {

    public abstract Object convert(Map<String, Object> attributes);
}
}
