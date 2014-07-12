using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using Cassandra;

namespace AspNet.Identity.Cassandra
{
    /// <summary>
    /// Helper class for creating the schema tables needed.
    /// </summary>
    internal static class SchemaCreationHelper
    {
        private static readonly Assembly CqlAssembly = typeof (SchemaCreationHelper).Assembly;
        private const string CqlScript = "AspNet.Identity.Cassandra.defaultschema.cql";

        /// <summary>
        /// Creates the schema if it doesn't exist.
        /// </summary>
        public static void CreateSchemaIfNotExists(ISession session)
        {
            var cqlStatements = new List<string>();

            // Read the CQL script in from the embedded resource
            using (var stream = CqlAssembly.GetManifestResourceStream(CqlScript))
            {
                if (stream == null)
                    throw new InvalidOperationException(string.Format("Could not find CQL script resource {0}", CqlScript));

                using (var reader = new StreamReader(stream))
                {
                    string currentLine;
                    var cqlStatement = new StringBuilder();
                    while ((currentLine = reader.ReadLine()) != null)
                    {
                        // Do some basic parsing
                        currentLine = currentLine.Trim();
                        
                        // Skip comment lines and empty lines
                        if (currentLine.StartsWith("//") || currentLine == string.Empty)
                            continue;

                        // Add line to current cql statement
                        cqlStatement.AppendFormat("{0} ", currentLine);

                        // If the line ends with a semi-colon, consider it the end of the statement
                        if (currentLine.EndsWith(";"))
                        {
                            cqlStatements.Add(cqlStatement.ToString());
                            cqlStatement.Clear();
                        }
                    }
                }
            }

            // Execute the CQL statements we parsed to create the schema
            foreach (string cql in cqlStatements)
            {
                session.Execute(cql);
            }
        }
    }
}
