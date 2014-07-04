using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AspNet.Identity.Cassandra.Cassandra;
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

        private Session _session;
        private UserContext _userContext;

        public CassandraUserStore(Session session)
        {
            try
            {
                session.ChangeKeyspace("users");
            }
            catch (InvalidQueryException)
            {
                session.CreateKeyspaceIfNotExists("users");
                session.ChangeKeyspace("users");
            }
            _session = session;
            
            _userContext = new UserContext(session);
        }

        public async Task CreateAsync(TUser user)
        {
            var prepared =
                _session.Prepare(
                    "INSERT into users.users (Id, UserName, Passwordhash, Securitystamp) VALUES (?, ?, ?, ?)");
            var bound = prepared.Bind(user.UserName, user.PasswordHash, user.SecurityStamp);
            await _session.ExecuteAsync(bound);
        }

        public async Task UpdateAsync(TUser user)
        {
            var prepared = _session.Prepare("UPDATE users SET passwordhash = ?, securitystamp = ? WHERE username = ?");
            var bound = prepared.Bind(user.PasswordHash, user.SecurityStamp, user.UserName);
            await _session.ExecuteAsync(bound);
        }
        
        public async Task DeleteAsync(TUser user)
        {
            var prepared = _session.Prepare("DELETE from users where username = ?");
            var bound = prepared.Bind(user.UserName);
            await _session.ExecuteAsync(bound);
        }

        public Task<TUser> FindByIdAsync(string userId)
        {
            var prepared = _session.Prepare("SELECT * FROM users where userId = ?");
            var bound = prepared.Bind(userId);
            var rows = _session.Execute(bound);
            var row = rows.Single();
            var user = new CassandraUser
            {
                Id = row.GetValue<Guid>("userId").ToString(),
                PasswordHash = row.GetValue<string>("passwordHash"),
                SecurityStamp = row.GetValue<string>("securityStamp"),
                UserName = row.GetValue<string>("userName")
            };
            return Task.FromResult((TUser)user);
        }

        public Task<TUser> FindByNameAsync(string userName)
        {
            var table = _session.GetTable<TUser>();
            var userQuery = table.FirstOrDefault(u => u.UserName == userName);
            var rows = _session.Execute(userQuery);
            var row = rows.Single();
            var user = MapRowToUser(row);
            return Task.FromResult((TUser) user);
        }

        private static CassandraUser MapRowToUser(Row row)
        {
            var user = new CassandraUser
            {
                Id = row.GetValue<Guid>("userId").ToString(),
                PasswordHash = row.GetValue<string>("passwordHash"),
                SecurityStamp = row.GetValue<string>("securityStamp"),
                UserName = row.GetValue<string>("userName")
            };
            return user;
        }

        public async Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            var prepared =
                _session.Prepare(
                    "INSERT into users.login (Id, UserId, LoginProvider, ProviderKey) VALUES (?, ?, ?, ?)");
            var bound = prepared.Bind(CassandraUserLogin.GenerateKey(login.LoginProvider, login.ProviderKey), user.Id, login.LoginProvider, login.ProviderKey);
            await _session.ExecuteAsync(bound);
        }

        public async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            var prepared =
                _session.Prepare(
                    "DELETE FROM users.login WHERE Id = ?");
            var bound = prepared.Bind(CassandraUserLogin.GenerateKey(login.LoginProvider, login.ProviderKey));
            await _session.ExecuteAsync(bound);
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            var prepared = _session.Prepare("SELECT * FROM users.login WHERE userId = ?");
            var bound = prepared.Bind(user.Id);
            var rows = await _session.ExecuteAsync(bound);
            return rows.Select(row => new UserLoginInfo(row.GetValue<string>("userId"), row.GetValue<string>("providerKey"))).ToList();
        }

        public Task<TUser> FindAsync(UserLoginInfo login)
        {
            var prepared = _session.Prepare("SELECT * FROM users.login where loginProvider = ? AND providerKey = ?");
            var bound = prepared.Bind(login.LoginProvider, login.ProviderKey);
            var row = _session.Execute(bound).FirstOrDefault();
            prepared = _session.Prepare("SELECT * FROM users where userId = ?");
            bound = prepared.Bind(row.GetValue<int>("userId"));
            row = _session.Execute(bound).FirstOrDefault();
            return Task.FromResult((TUser) MapRowToUser(row));
        }

        public async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            var prepared = _session.Prepare("SELECT * FROM users.claim WHERE userId = ?");
            var bound = prepared.Bind(user.Id);
            var rows = await _session.ExecuteAsync(bound);
            return rows.Select(row => new Claim(row.GetValue<string>("type"), row.GetValue<string>("value"), row.GetValue<string>("valueType"), row.GetValue<string>("issuer"), row.GetValue<string>("originalissuer"))).ToList();
        }

        public async Task AddClaimAsync(TUser user, Claim claim)
        {
            var prepared =
                _session.Prepare(
                    "INSERT into users.claim (Id, UserId, Issuer, OriginalIssuer, Subject, Type, Value, ValueType");
            var bound = prepared.Bind(CassandraUserClaim.GenerateKey(user.Id, claim.Issuer, claim.Type), user.Id,
                claim.Issuer, claim.OriginalIssuer, claim.Subject, claim.Type, claim.Value, claim.ValueType);
            await _session.ExecuteAsync(bound);
        }

        public Task RemoveClaimAsync(TUser user, Claim claim)
        {
            //var prepared = _session.Prepare("DELETE from users.claim where username = ?");
            //var bound = prepared.Bind(user.UserName);
            //await _session.ExecuteAsync(bound);
            throw new NotImplementedException();
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            user.SetPasswordHash(passwordHash);
            return Task.FromResult(0);
        }

        public Task<string> GetPasswordHashAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> HasPasswordAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetSecurityStampAsync(TUser user, string stamp)
        {
            user.SetSecurityStamp(stamp);
            return Task.FromResult(0);
        }

        public Task<string> GetSecurityStampAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public IQueryable<TUser> Users { get; private set; }
        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            throw new NotImplementedException();
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task ResetAccessFailedCountAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<int> GetAccessFailedCountAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailAsync(TUser user, string email)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetEmailAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            throw new NotImplementedException();
        }

        public Task<TUser> FindByEmailAsync(string email)
        {
            throw new NotImplementedException();
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetPhoneNumberAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            throw new NotImplementedException();
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
