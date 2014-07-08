using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Identity.Cassandra.Entities;
using Cassandra;
using Cassandra.Data.Linq;
using Microsoft.AspNet.Identity;

namespace AspNet.Identity.Cassandra.Store
{
    public class CassandraUserStore<TUser, TKey> : IUserStore<TUser, TKey>
        // IUserLoginStore<TUser>,
        // IUserClaimStore<TUser>,
        // IUserPasswordStore<TUser>,
        // IUserSecurityStampStore<TUser>,
        // IQueryableUserStore<TUser>,
        // IUserTwoFactorStore<TUser, string>,
        // IUserLockoutStore<TUser, string>,
        // IUserEmailStore<TUser>,
        // IUserPhoneNumberStore<TUser> 
        where TUser : CassandraUser<TKey>, new ()
    {
        // A cached copy of a completed task
        private static readonly Task CompletedTask = Task.FromResult(true);

        private readonly ISession _session;

        // Reusable prepared statements, lazy evaluated
        private readonly AsyncLazy<PreparedStatement[]> _createUser;
        private readonly AsyncLazy<PreparedStatement[]> _deleteUser;

        private readonly AsyncLazy<PreparedStatement> _findById;
        private readonly AsyncLazy<PreparedStatement> _findByName;

        private readonly AsyncLazy<PreparedStatement> _addLogin;
        private readonly AsyncLazy<PreparedStatement> _removeLogin;
        private readonly AsyncLazy<PreparedStatement> _getLogins;
        private readonly AsyncLazy<PreparedStatement> _getLoginsByProvider;

        private readonly AsyncLazy<PreparedStatement> _getClaims;
        private readonly AsyncLazy<PreparedStatement> _addClaim;
        private readonly AsyncLazy<PreparedStatement> _removeClaim; 

        public IQueryable<TUser> Users { get; private set; }

        public CassandraUserStore(ISession session)
        {
            _session = session;

            // TODO:  Currently broken because no attributes on POCOs
            // _session.GetTable<CassandraUser>().CreateIfNotExists();
            // _session.GetTable<CassandraUserClaim>().CreateIfNotExists();
            // _session.GetTable<CassandraUserLogin>().CreateIfNotExists();

            // Create some reusable prepared statements so we pay the cost of preparing once, then bind multiple times
            _createUser = new AsyncLazy<PreparedStatement[]>(() => Task.WhenAll(new []
            {
                _session.PrepareAsync("INSERT INTO users (id, username) VALUES (?, ?)"),
                _session.PrepareAsync("INSERT INTO users_by_username (username, id) VALUES (?, ?)")
            }));
            _deleteUser = new AsyncLazy<PreparedStatement[]>(() => Task.WhenAll(new []
            {
                _session.PrepareAsync("DELETE FROM users WHERE id = ?"),
                _session.PrepareAsync("DELETE FROM users_by_username WHERE username = ?")
            }));
            _findById = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync("SELECT * FROM users WHERE id = ?"));
            _findByName = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync("SELECT * FROM users_by_username WHERE username = ?"));
            
            _addLogin = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync(
                "INSERT INTO logins (userId, LoginProvider, ProviderKey) VALUES (?, ?, ?)"));
            _removeLogin = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync(
                "DELETE FROM logins WHERE userId = ? and loginprovider = ? and providerkey = ?"));
            _getLogins = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync("SELECT * FROM logins WHERE userId = ?"));
            _getLoginsByProvider = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync(
                "SELECT * FROM logins WHERE loginProvider = ? AND providerKey = ? ALLOW FILTERING"));

            _getClaims = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync("SELECT * FROM claims WHERE userId = ? ALLOW FILTERING"));
            _addClaim = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync(
                "INSERT INTO claims (UserId, Issuer, OriginalIssuer, Type, Value, ValueType) VALUES (?, ?, ?, ?, ?, ?, ?)"));
            _removeClaim = new AsyncLazy<PreparedStatement>(() => _session.PrepareAsync(
                "DELETE FROM claims WHERE userId = ? AND value = ? AND type = ?"));
        }

        /// <summary>
        /// Insert a new user.
        /// </summary>
        public async Task CreateAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            // TODO:  Support uniqueness for usernames/emails at the C* level using LWT?

            PreparedStatement[] prepared = await _createUser;
            var batch = new BatchStatement();

            // INSERT INTO users ...
            batch.Add(prepared[0].Bind(user.Id, user.UserName));

            // INSERT INTO users_by_username ...
            batch.Add(prepared[1].Bind(user.UserName, user.Id));

            await _session.ExecuteAsync(batch).ConfigureAwait(false);
        }

        /// <summary>
        /// Update a user.
        /// </summary>
        public Task UpdateAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            // Right now, since the only things being persisted for user are Id (which can't change) and username, which
            // we currently assume can't change, this is a No-Op
            // TODO:  Support updating username?

            return CompletedTask;
        }

        /// <summary>
        /// Delete a user.
        /// </summary>
        public async Task DeleteAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            PreparedStatement[] prepared = await _deleteUser;
            var batch = new BatchStatement();

            // DELETE FROM users ...
            batch.Add(prepared[0].Bind(user.Id));

            // DELETE FROM users_by_username ...
            batch.Add(prepared[1].Bind(user.UserName));
            
            await _session.ExecuteAsync(batch).ConfigureAwait(false);
        }

        /// <summary>
        /// Finds a user by userId.
        /// </summary>
        public async Task<TUser> FindByIdAsync(TKey userId)
        {
            PreparedStatement prepared = await _findById;
            BoundStatement bound = prepared.Bind(userId);

            RowSet rows = await _session.ExecuteAsync(bound).ConfigureAwait(false);
            return MapRowToCassandraUser(rows.SingleOrDefault());
        }

        /// <summary>
        /// Find a user by name (assumes usernames are unique).
        /// </summary>
        public async Task<TUser> FindByNameAsync(string userName)
        {
            if (string.IsNullOrWhiteSpace(userName)) throw new ArgumentException("userName cannot be null or empty", "userName");
            
            PreparedStatement prepared = await _findByName;
            BoundStatement bound = prepared.Bind(userName);

            RowSet rows = await _session.ExecuteAsync(bound).ConfigureAwait(false);
            return MapRowToCassandraUser(rows.SingleOrDefault());
        }

        private static TUser MapRowToCassandraUser(Row row)
        {
            if (row == null) return null;

            return new TUser
            {
                Id = row.GetValue<TKey>("id"),
                UserName = row.GetValue<string>("username")
            };
        }

        public Task<TUser> FindByEmailAsync(string email)
        {
            throw new NotImplementedException("This method does not function currently");
            //var prepared = _session.Prepare("SELECT * FROM users where email = ? ALLOW FILTERING");
            //var bound = prepared.Bind(email);
            //var row = _session.Execute(bound).FirstOrDefault();
            //var user = MapRowToUser(row);
            //return Task.FromResult((TUser)user);
        }
        
        private static CassandraUser MapRowToUser(Row row)
        {
            if (row == null)
                return new CassandraUser();

            var user = new CassandraUser
            {
                PasswordHash = row.GetValue<string>("passwordhash"),
                SecurityStamp = row.GetValue<string>("securitystamp"),
                UserName = row.GetValue<string>("username"),
                IsTwoFactorEnabled = row.GetValue<bool>("istwofactorenabled"),
                AccessFailedCount = row.GetValue<int>("accessfailedcount"),
                Email = row.GetValue<string>("email"),
                EmailConfirmedOn = row.GetValue<DateTimeOffset?>("emailconfirmedon"),
                IsLockoutEnabled = row.GetValue<bool>("islockoutenabled"),
                LockoutEndDate = row.GetValue<DateTimeOffset?>("lockoutenddate")
            };
            return user;
        }

        public async Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (login == null) throw new ArgumentNullException("login");

            PreparedStatement prepared = await _addLogin;
            BoundStatement bound = prepared.Bind(user.Id, login.LoginProvider, login.ProviderKey);

            await _session.ExecuteAsync(bound).ConfigureAwait(false);
        }

        public async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (login == null) throw new ArgumentNullException("login");

            PreparedStatement prepared = await _removeLogin;
            BoundStatement bound = prepared.Bind(user.Id, login.LoginProvider, login.ProviderKey);

            await _session.ExecuteAsync(bound).ConfigureAwait(false);
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            PreparedStatement prepared = await _getLogins;
            BoundStatement bound = prepared.Bind(user.Id);

            RowSet rows = await _session.ExecuteAsync(bound).ConfigureAwait(false);
            return rows.Select(row => new UserLoginInfo(row.GetValue<string>("loginprovider"), row.GetValue<string>("providerkey"))).ToList();
        }

        public async Task<TUser> FindAsync(UserLoginInfo login)
        {
            if (login == null) throw new ArgumentNullException("login");

            PreparedStatement prepared = await _getLoginsByProvider;
            BoundStatement bound = prepared.Bind(login.LoginProvider, login.ProviderKey);

            RowSet logins = await _session.ExecuteAsync(bound).ConfigureAwait(false);
            Row loginResult = logins.FirstOrDefault();
            if (loginResult == null)
                return null;

            prepared = await _findById;
            bound = prepared.Bind(loginResult.GetValue<string>("userid"));

            RowSet rows = await _session.ExecuteAsync(bound).ConfigureAwait(false);
            Row row = rows.FirstOrDefault();
            return (TUser) MapRowToUser(row);
        }

        public async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            PreparedStatement prepared = await _getClaims;
            BoundStatement bound = prepared.Bind(user.Id);

            RowSet rows = await _session.ExecuteAsync(bound).ConfigureAwait(false);
            return rows.Select(row => new Claim(row.GetValue<string>("type"), row.GetValue<string>("value"), row.GetValue<string>("valuetype"),
                                                row.GetValue<string>("issuer"), row.GetValue<string>("originalissuer"))).ToList();
        }

        public async Task AddClaimAsync(TUser user, Claim claim)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (claim == null) throw new ArgumentNullException("claim");

            PreparedStatement prepared = await _addClaim;
            BoundStatement bound = prepared.Bind(user.Id, claim.Issuer, claim.OriginalIssuer, claim.Type, claim.Value, claim.ValueType);
            await _session.ExecuteAsync(bound).ConfigureAwait(false);
        }

        public async Task RemoveClaimAsync(TUser user, Claim claim)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (claim == null) throw new ArgumentNullException("claim");

            PreparedStatement prepared = await _removeClaim;
            BoundStatement bound = prepared.Bind(user.Id, claim.Value, claim.Type);

            await _session.ExecuteAsync(bound).ConfigureAwait(false);
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (passwordHash == null) throw new ArgumentNullException("passwordHash");

            user.SetPasswordHash(passwordHash);
            return Task.FromResult(0);
        }

        public Task<string> GetPasswordHashAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(string.IsNullOrEmpty(user.PasswordHash) == false);
        }

        public Task SetSecurityStampAsync(TUser user, string stamp)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (stamp == null) throw new ArgumentNullException("stamp");

            user.SetSecurityStamp(stamp);
            return Task.FromResult(0);
        }

        public Task<string> GetSecurityStampAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(user.SecurityStamp);
        }
        
        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            if (user == null) throw new ArgumentNullException("user");

            user.IsTwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(user.IsTwoFactorEnabled);
        }

        public Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");
            if(user.LockoutEndDate == null) throw new InvalidOperationException("LockoutEndDate has no value.");

            return Task.FromResult(user.LockoutEndDate.Value);
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            if (user == null) throw new ArgumentNullException("user");

            user.LockoutEndDate = lockoutEnd;
            return Task.FromResult(0);
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            user.AccessFailedCount++;
            return Task.FromResult(0);
        }

        public Task ResetAccessFailedCountAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(user.IsLockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            if (user == null) throw new ArgumentNullException("user");

            user.IsLockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task SetEmailAsync(TUser user, string email)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (email == null) throw new ArgumentNullException("email");

            user.Email = email;
            return Task.FromResult(0);
        }

        public Task<string> GetEmailAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(user.EmailConfirmedOn != null);
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            if (user == null) throw new ArgumentNullException("user");

            if (confirmed)
            {
                user.EmailConfirmedOn = DateTime.Now;
            }
            else
            {
                user.EmailConfirmedOn = null;
            }
            return Task.FromResult(0);
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (phoneNumber == null) throw new ArgumentNullException("phoneNumber");

            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(user.PhoneNumberConfirmedOn != null);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            if (user == null) throw new ArgumentNullException("user");

            if (confirmed)
            {
                user.PhoneNumberConfirmedOn = DateTime.Now;
            }
            else
            {
                user.PhoneNumberConfirmedOn = null;
            }
            return Task.FromResult(0);
        }


        protected void Dispose(bool disposing)
        {
            _session.Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
