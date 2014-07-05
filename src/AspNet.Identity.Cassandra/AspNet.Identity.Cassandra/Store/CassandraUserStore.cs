﻿using System;
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

        public CassandraUserStore(ISession session)
        {
            _session = session;
            _session.GetTable<CassandraUser>().CreateIfNotExists();
            _session.GetTable<CassandraUserClaim>().CreateIfNotExists();
            _session.GetTable<CassandraUserLogin>().CreateIfNotExists();
        }

        public async Task CreateAsync(TUser user)
        {
            var prepared =
                _session.Prepare(
                    "INSERT into users (Id, UserName, Passwordhash, Securitystamp, islockoutenabled, istwofactorenabled, email, accessfailedcount, lockoutenddate, phonenumber) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            var bound = prepared.Bind(CassandraUser.GenerateKey(user.UserName), user.UserName, user.PasswordHash, user.SecurityStamp, user.IsLockoutEnabled, user.IsTwoFactorEnabled, user.Email, user.AccessFailedCount, user.LockoutEndDate, user.PhoneNumber);
            await _session.ExecuteAsync(bound);
        }

        public async Task UpdateAsync(TUser user)
        {
            var prepared = _session.Prepare("UPDATE users SET passwordhash = ?, securitystamp = ?, islockoutenabled = ?, istwofactorenabled = ?, email = ?, accessfailedcount = ?, lockoutenddate = ?, phonenumber = ? WHERE id = ? and username = ?");
            var bound = prepared.Bind(user.PasswordHash, user.SecurityStamp, user.IsLockoutEnabled, user.IsTwoFactorEnabled, user.Email, user.AccessFailedCount, user.LockoutEndDate, user.PhoneNumber, user.Id, user.UserName);
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
            var prepared = _session.Prepare("SELECT * FROM users where id = ?");
            var bound = prepared.Bind(userId);
            var rows = _session.Execute(bound);
            var row = rows.Single();
            var user = MapRowToUser(row);
            return Task.FromResult((TUser)user);
        }

        public Task<TUser> FindByNameAsync(string userName)
        {
            var prepared = _session.Prepare("SELECT * FROM users where username = ? ALLOW FILTERING");
            var bound = prepared.Bind(userName);
            var rows = _session.Execute(bound);
            var row = rows.FirstOrDefault();
            var user = row == null ? null : MapRowToUser(row);
            return Task.FromResult((TUser) user);
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
            var prepared =
                _session.Prepare(
                    "INSERT into logins (Id, userId, LoginProvider, ProviderKey) VALUES (?, ?, ?, ?)");
            var bound = prepared.Bind(CassandraUserLogin.GenerateKey(login.LoginProvider, login.ProviderKey), user.Id, login.LoginProvider, login.ProviderKey);
            await _session.ExecuteAsync(bound);
        }

        public async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            var prepared =
                _session.Prepare(
                    "DELETE FROM logins WHERE Id = ?");
            var bound = prepared.Bind(CassandraUserLogin.GenerateKey(login.LoginProvider, login.ProviderKey));
            await _session.ExecuteAsync(bound);
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            var prepared = _session.Prepare("SELECT * FROM logins WHERE userId = ?");
            var bound = prepared.Bind(user.Id);
            var rows = await _session.ExecuteAsync(bound);
            return rows.Select(row => new UserLoginInfo(row.GetValue<string>("userId"), row.GetValue<string>("providerKey"))).ToList();
        }

        public Task<TUser> FindAsync(UserLoginInfo login)
        {
            var prepared = _session.Prepare("SELECT * FROM logins where loginProvider = ? AND providerKey = ? ALLOW FILTERING");
            var bound = prepared.Bind(login.LoginProvider, login.ProviderKey);
            var row = _session.Execute(bound).FirstOrDefault();
            if (row == null)
                return Task.FromResult((TUser) null);
            prepared = _session.Prepare("SELECT * FROM users where id = ?");
            bound = prepared.Bind(row.GetValue<string>("userid"));
            row = _session.Execute(bound).FirstOrDefault();
            return Task.FromResult((TUser) MapRowToUser(row));
        }

        public async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            var prepared = _session.Prepare("SELECT * FROM claims WHERE userId = ? ALLOW FILTERING");
            var bound = prepared.Bind(user.Id);
            var rows = await _session.ExecuteAsync(bound);
            return rows.Select(row => new Claim(row.GetValue<string>("type"), row.GetValue<string>("value"), row.GetValue<string>("valuetype"), row.GetValue<string>("issuer"), row.GetValue<string>("originalissuer"))).ToList();
        }

        public async Task AddClaimAsync(TUser user, Claim claim)
        {
            var prepared =
                _session.Prepare(
                    "INSERT into claims (Id, UserId, Issuer, OriginalIssuer, Type, Value, ValueType) VALUES (?, ?, ?, ?, ?, ?, ?)");
            var bound = prepared.Bind(CassandraUserClaim.GenerateKey(user.Id, claim.Issuer, claim.Type), user.Id,
                claim.Issuer, claim.OriginalIssuer, claim.Type, claim.Value, claim.ValueType);
            await _session.ExecuteAsync(bound);
        }

        public Task RemoveClaimAsync(TUser user, Claim claim)
        {
            var prepared = _session.Prepare("Delete from claims where userId = ? and value = ? and type = ?");
            var bound = prepared.Bind(user.Id, claim.Value, claim.Type);
            _session.Execute(bound);
            return Task.FromResult<object>(null);
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            user.SetPasswordHash(passwordHash);
            return Task.FromResult(0);
        }

        public Task<string> GetPasswordHashAsync(TUser user)
        {
            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(TUser user)
        {
            return Task.FromResult(string.IsNullOrEmpty(user.PasswordHash) == false);
        }

        public Task SetSecurityStampAsync(TUser user, string stamp)
        {
            user.SetSecurityStamp(stamp);
            return Task.FromResult(0);
        }

        public Task<string> GetSecurityStampAsync(TUser user)
        {
            return Task.FromResult(user.SecurityStamp);
        }

        public IQueryable<TUser> Users { get; private set; }
        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            user.IsTwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            return Task.FromResult(user.IsTwoFactorEnabled);
        }

        public Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            return Task.FromResult(user.LockoutEndDate.Value);
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            user.LockoutEndDate = lockoutEnd;
            return Task.FromResult(0);
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            user.AccessFailedCount++;
            return Task.FromResult(0);
        }

        public Task ResetAccessFailedCountAsync(TUser user)
        {
            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(TUser user)
        {
            var cUser = FindByIdAsync(user.Id).Result;
            return Task.FromResult(cUser.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            var cUser = FindByIdAsync(user.Id).Result;
            return Task.FromResult(cUser.IsLockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            user.IsLockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task SetEmailAsync(TUser user, string email)
        {
            user.Email = email;
            return Task.FromResult(0);
        }

        public Task<string> GetEmailAsync(TUser user)
        {
            var cUser = FindByIdAsync(user.Id).Result;
            return Task.FromResult(cUser.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            var cUser = FindByIdAsync(user.Id).Result;
            return Task.FromResult(cUser.EmailConfirmedOn != null);
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
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

        public Task<TUser> FindByEmailAsync(string email)
        {
            var prepared = _session.Prepare("SELECT * FROM users where email = ?");
            var bound = prepared.Bind(email);
            var row = _session.Execute(bound).FirstOrDefault();
            var user = MapRowToUser(row);
            return Task.FromResult((TUser) user);
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(TUser user)
        {
            var cUser = FindByIdAsync(user.Id).Result;
            return Task.FromResult(cUser.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            var cUser = FindByIdAsync(user.Id).Result;
            return Task.FromResult(cUser.PhoneNumberConfirmedOn != null);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
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