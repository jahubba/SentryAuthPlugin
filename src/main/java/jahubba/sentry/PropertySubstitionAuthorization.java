package jahubba.sentry;

import static org.apache.sentry.provider.common.ProviderConstants.AUTHORIZABLE_JOINER;
import static org.apache.sentry.provider.common.ProviderConstants.AUTHORIZABLE_SPLITTER;
import static org.apache.sentry.provider.common.ProviderConstants.KV_JOINER;
import static org.apache.sentry.provider.common.ProviderConstants.PRIVILEGE_NAME;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.text.StrSubstitutor;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.Groups;
import org.apache.log4j.Logger;
import org.apache.sentry.core.common.Action;
import org.apache.sentry.core.common.ActiveRoleSet;
import org.apache.sentry.core.common.Authorizable;
import org.apache.sentry.core.common.Subject;
import org.apache.sentry.policy.common.PolicyEngine;
import org.apache.sentry.policy.common.Privilege;
import org.apache.sentry.policy.common.PrivilegeFactory;
import org.apache.sentry.provider.common.GroupMappingService;
import org.apache.sentry.provider.common.HadoopGroupMappingService;
import org.apache.sentry.provider.common.HadoopGroupResourceAuthorizationProvider;

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

public class PropertySubstitionAuthorization extends HadoopGroupResourceAuthorizationProvider {

	private static final Logger LOGGER = Logger.getLogger(PropertySubstitionAuthorization.class);

	private final PrivilegeFactory privilegeFactory;
	
	private final PolicyEngine policy;

	public PropertySubstitionAuthorization(String resource, PolicyEngine policy) throws IOException {
		this(policy, new HadoopGroupMappingService(Groups.getUserToGroupsMappingService(new Configuration())));
	}

	public PropertySubstitionAuthorization(Configuration conf, String resource, PolicyEngine policy) throws IOException {
		this(policy, new HadoopGroupMappingService(Groups.getUserToGroupsMappingService(conf)));
	}

	public PropertySubstitionAuthorization(PolicyEngine policy, GroupMappingService groupService) {
		super(policy, groupService);
		this.policy = policy;
		this.privilegeFactory = policy.getPrivilegeFactory();
	}

	@Override
	public boolean hasAccess(Subject subject, List<? extends Authorizable> authorizableHierarchy,
			Set<? extends Action> actions, ActiveRoleSet roleSet) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Authorization Request for " + subject + " " + authorizableHierarchy + " and " + actions);
		}
		Preconditions.checkNotNull(subject, "Subject cannot be null");
		Preconditions.checkNotNull(authorizableHierarchy, "Authorizable cannot be null");
		Preconditions.checkArgument(!authorizableHierarchy.isEmpty(), "Authorizable cannot be empty");
		Preconditions.checkNotNull(actions, "Actions cannot be null");
		Preconditions.checkArgument(!actions.isEmpty(), "Actions cannot be empty");
		Preconditions.checkNotNull(roleSet, "ActiveRoleSet cannot be null");

		Set<String> groups = getGroups(subject);
		Iterable<Privilege> privileges = getPrivileges(subject.getName(), groups, roleSet, authorizableHierarchy.toArray(new Authorizable[0]));
		List<String> requestPrivileges = buildPermissions(authorizableHierarchy, actions);
	    for (String requestPrivilege : requestPrivileges) {
	        for (Privilege permission : privileges) {
	          /*
	           * Does the permission granted in the policy file imply the requested action?
	           */
	          boolean result = permission.implies(privilegeFactory.createPrivilege(requestPrivilege));
	          if(LOGGER.isDebugEnabled()) {
	        	  LOGGER.info(String.format("ProviderPrivilege %s, RequestPrivilege %s, RoleSet, %s, Result %s", permission,
							requestPrivilege, roleSet, result));
	          }
	          if (result) {
	            return true;
	          }
	        }
	      }

		return super.hasAccess(subject, authorizableHierarchy, actions, roleSet);
	}

	private Set<String> getGroups(Subject subject) {
		return getGroupMapping().getGroups(subject.getName());
	}

	private List<String> buildPermissions(List<? extends Authorizable> authorizables, Set<? extends Action> actions) {
		List<String> hierarchy = new ArrayList<String>();
		List<String> requestedPermissions = new ArrayList<String>();

		for (Authorizable authorizable: authorizables) {
			hierarchy.add(KV_JOINER.join(authorizable.getTypeName(), authorizable.getName()));
		}

		for (Action action: actions) {
			String requestPermission = AUTHORIZABLE_JOINER.join(hierarchy);
			requestPermission =
					AUTHORIZABLE_JOINER.join(requestPermission, KV_JOINER.join(PRIVILEGE_NAME, action.getValue()));
			requestedPermissions.add(requestPermission);
		}
		return requestedPermissions;
	}

	private Iterable<Privilege> getPrivileges(String subject, Set<String> groups, ActiveRoleSet roleSet, Authorizable[] authorizables) {
		Map<String, String> props = new HashMap<String, String>(1);
		props.put("user", subject);
		final StrSubstitutor sub = new StrSubstitutor(props);
		//TODO, this will get all priveleges, can it but reduced?
		return Iterables.transform(appendDefaultDBPriv(policy.getPrivileges(groups, roleSet, null), authorizables),
				new Function<String, Privilege>() {
					@Override
					public Privilege apply(String privilege) {
						return privilegeFactory.createPrivilege(sub.replace(privilege));
					}
				});
	}

	private ImmutableSet<String> appendDefaultDBPriv(ImmutableSet<String> privileges, Authorizable[] authorizables) {
		// Only for switch db
		if ((authorizables != null) && (authorizables.length == 3) && (authorizables[2].getName().equals("+"))) {
			if ((privileges.size() == 1) && hasOnlyServerPrivilege(privileges.asList().get(0))) {
				// Assuming authorizable[0] will always be the server
				// This Code is only reachable only when user fires a 'use default'
				// and the user has a privilege on atleast 1 privilized Object
				String defaultPriv = "Server=" + authorizables[0].getName() + "->Db=default->Table=*->action=select";
				HashSet<String> newPrivs = Sets.newHashSet(defaultPriv);
				return ImmutableSet.copyOf(newPrivs);
			}
		}
		return privileges;
	}

	private boolean hasOnlyServerPrivilege(String priv) {
		ArrayList<String> l = Lists.newArrayList(AUTHORIZABLE_SPLITTER.split(priv));
		if ((l.size() == 1) && (l.get(0).toLowerCase().startsWith("server"))) {
			return l.get(0).toLowerCase().split("=")[1].endsWith("+");
		}
		return false;
	}

}
