﻿namespace AspNet.Identity.Cassandra
{
    public static class Constants
    {
        internal const string CassandraUserKeyTemplate = "CassandraUsers/{0}";
        internal const string CassandraUserLoginKeyTemplate = "CassandraUserLogins/{0}/{1}";
        internal const string CassandraUserEmailKeyTemplate = "CassandraUserEmails/{0}";
        internal const string CassandraUserPhoneNumberKeyTemplate = "CassandraUserPhoneNumbers/{0}";
        internal const string CassandraUserClaim = "CassandraUserClaim/{0}/{1}/{2}";
    }
}