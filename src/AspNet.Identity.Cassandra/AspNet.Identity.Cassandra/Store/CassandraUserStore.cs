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
    public class CassandraUserStore<TUser> : IUserStore<TUser>,
        IUserLoginStore<TUser>,
        IUserClaimStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,
        IQueryableUserStore<TUser>,
        IUserTwoFactorStore<TUser, string>,
        IUserLockoutStore<TUser, string>,
        IUserEmailStore<TUser>,
        IUserPhoneNumberStore<TUser> where TUser : CassandraUser
    {

        private readonly ISession _session;
        public IQueryable<TUser> Users { get; private set; }
        public CassandraUserStore(ISession session)
        {
            _session = session;
            _session.GetTable<CassandraUser>().CreateIfNotExists();
            _session.GetTable<CassandraUserClaim>().CreateIfNotExists();
            _session.GetTable<CassandraUserLogin>().CreateIfNotExists();
        }

        public async Task CreateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            var prepared =
                _session.Prepare(
                    "INSERT into users (Id, UserName, Passwordhash, Securitystamp, islockoutenabled, istwofactorenabled, email, accessfailedcount, lockoutenddate, phonenumber) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            var bound = prepared.Bind(CassandraUser.GenerateKey(user.UserName), user.UserName, user.PasswordHash, user.SecurityStamp, user.IsLockoutEnabled, user.IsTwoFactorEnabled, user.Email, user.AccessFailedCount, user.LockoutEndDate, user.PhoneNumber);
            await _session.ExecuteAsync(bound);
        }

        public Task UpdateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            var prepared = _session.Prepare("UPDATE users SET passwordhash = ?, securitystamp = ?, islockoutenabled = ?, istwofactorenabled = ?, email = ?, accessfailedcount = ?, lockoutenddate = ?, phonenumber = ? WHERE id = ? and username = ?");
            var bound = prepared.Bind(user.PasswordHash, user.SecurityStamp, user.IsLockoutEnabled, user.IsTwoFactorEnabled, user.Email, user.AccessFailedCount, user.LockoutEndDate, user.PhoneNumber, user.Id, user.UserName);
            return _session.ExecuteAsync(bound);
        }
        
        public Task DeleteAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            var prepared = _session.Prepare("DELETE from users where id = ?");
            var bound = prepared.Bind(user.Id);
            return _session.ExecuteAsync(bound);
        }

        public async Task<TUser> FindByIdAsync(string userId)
        {
            if (userId == null)
            {
                throw new ArgumentNullException("userId");
            }
            var prepared = _session.Prepare("SELECT * FROM users where id = ?");
            var bound = prepared.Bind(userId);
            var rows = await _session.ExecuteAsync(bound);
            var row = rows.SingleOrDefault();
            var user = MapRowToUser(row);
            return (TUser)user;
        }

        public async Task<TUser> FindByNameAsync(string userName)
        {
            if (userName == null)
            {
                throw new ArgumentNullException("userName");
            }
            var prepared = _session.Prepare("SELECT * FROM users where username = ? ALLOW FILTERING");
            var bound = prepared.Bind(userName);
            var rows = await _session.ExecuteAsync(bound);
            var row = rows.FirstOrDefault();
            var user = row == null ? null : MapRowToUser(row);
            return (TUser) user;
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
                Id = row.GetValue<string>("id"),
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

            var prepared =
                _session.Prepare(
                    "INSERT into logins (Id, userId, LoginProvider, ProviderKey) VALUES (?, ?, ?, ?)");
            var bound = prepared.Bind(CassandraUserLogin.GenerateKey(login.LoginProvider, login.ProviderKey), user.Id, login.LoginProvider, login.ProviderKey);
            await _session.ExecuteAsync(bound);
        }

        public async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (login == null) throw new ArgumentNullException("login");

            var prepared =
                _session.Prepare(
                    "DELETE FROM logins WHERE userId = ? and loginprovider = ? and providerkey = ?");
            var bound = prepared.Bind(user.Id, login.LoginProvider, login.ProviderKey);
            await _session.ExecuteAsync(bound);
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            var prepared = _session.Prepare("SELECT * FROM logins WHERE userId = ?");
            var bound = prepared.Bind(user.Id);
            var rows = await _session.ExecuteAsync(bound);
            return rows.Select(row => new UserLoginInfo(row.GetValue<string>("loginprovider"), row.GetValue<string>("providerkey"))).ToList();
        }

        public async Task<TUser> FindAsync(UserLoginInfo login)
        {
            if (login == null) throw new ArgumentNullException("login");

            var prepared = _session.Prepare("SELECT * FROM logins where loginProvider = ? AND providerKey = ? ALLOW FILTERING");
            var bound = prepared.Bind(login.LoginProvider, login.ProviderKey);
            var logins = await _session.ExecuteAsync(bound);
            var loginResult = logins.FirstOrDefault();
            if (loginResult == null)
                return null;
            prepared = _session.Prepare("SELECT * FROM users where id = ?");
            bound = prepared.Bind(loginResult.GetValue<string>("userid"));
            var row = _session.Execute(bound).FirstOrDefault();
            return (TUser) MapRowToUser(row);
        }

        public async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException("user");

            var prepared = _session.Prepare("SELECT * FROM claims WHERE userId = ? ALLOW FILTERING");
            var bound = prepared.Bind(user.Id);
            var rows = await _session.ExecuteAsync(bound);
            return rows.Select(row => new Claim(row.GetValue<string>("type"), row.GetValue<string>("value"), row.GetValue<string>("valuetype"), row.GetValue<string>("issuer"), row.GetValue<string>("originalissuer"))).ToList();
        }

        public async Task AddClaimAsync(TUser user, Claim claim)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (claim == null) throw new ArgumentNullException("claim");

            var prepared =
                _session.Prepare(
                    "INSERT into claims (Id, UserId, Issuer, OriginalIssuer, Type, Value, ValueType) VALUES (?, ?, ?, ?, ?, ?, ?)");
            var bound = prepared.Bind(CassandraUserClaim.GenerateKey(user.Id, claim.Issuer, claim.Type), user.Id,
                claim.Issuer, claim.OriginalIssuer, claim.Type, claim.Value, claim.ValueType);
            await _session.ExecuteAsync(bound);
        }

        public Task RemoveClaimAsync(TUser user, Claim claim)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (claim == null) throw new ArgumentNullException("claim");

            var prepared = _session.Prepare("Delete from claims where userId = ? and value = ? and type = ?");
            var bound = prepared.Bind(user.Id, claim.Value, claim.Type);
            return _session.ExecuteAsync(bound);
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
