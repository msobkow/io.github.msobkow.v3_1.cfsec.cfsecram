
// Description: Java 25 in-memory RAM DbIO implementation for SecTentRole.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecTentRoleTable in-memory RAM DbIO implementation
 *	for SecTentRole.
 */
public class CFSecRamSecTentRoleTable
	implements ICFSecSecTentRoleTable
{
	private ICFSecSchema schema;
	private Map< $implCommaIJavaOptAtomType$,
				CFSecBuffSecTentRole > dictByPKey
		= new HashMap< $implCommaIJavaOptAtomType$,
				CFSecBuffSecTentRole >();
	private Map< CFSecBuffSecTentRoleByTenantIdxKey,
				Map< $implCommaIJavaOptAtomType$,
					CFSecBuffSecTentRole >> dictByTenantIdx
		= new HashMap< CFSecBuffSecTentRoleByTenantIdxKey,
				Map< $implCommaIJavaOptAtomType$,
					CFSecBuffSecTentRole >>();
	private Map< CFSecBuffSecTentRoleByNameIdxKey,
				Map< $implCommaIJavaOptAtomType$,
					CFSecBuffSecTentRole >> dictByNameIdx
		= new HashMap< CFSecBuffSecTentRoleByNameIdxKey,
				Map< $implCommaIJavaOptAtomType$,
					CFSecBuffSecTentRole >>();
	private Map< CFSecBuffSecTentRoleByUNameIdxKey,
			CFSecBuffSecTentRole > dictByUNameIdx
		= new HashMap< CFSecBuffSecTentRoleByUNameIdxKey,
			CFSecBuffSecTentRole >();

	public CFSecRamSecTentRoleTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecTentRole ensureRec(ICFSecSecTentRole rec) {
		return (((CFSecBuffSecTentRoleFactoryService)(schema.getCFSecBuffFactory().getFactorySecTentRole())).ensureRec(rec));
	}

	@Override
	public ICFSecSecTentRole createSecTentRole( ICFSecAuthorization Authorization,
		ICFSecSecTentRole iBuff )
	{
		final String S_ProcName = "createSecTentRole";
		
		CFSecBuffSecTentRole Buff = (CFSecBuffSecTentRole)ensureRec(iBuff);
		$implCommaIJavaOptAtomType$ pkey;
		pkey = schema.nextSecTentRoleIdGen();
		Buff.setRequiredSecTentRoleId( pkey );
		CFSecBuffSecTentRoleByTenantIdxKey keyTenantIdx = (CFSecBuffSecTentRoleByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecBuffSecTentRoleByNameIdxKey keyNameIdx = (CFSecBuffSecTentRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByNameIdxKey();
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecTentRoleByUNameIdxKey keyUNameIdx = (CFSecBuffSecTentRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByUNameIdxKey();
		keyUNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecTentRoleUNameIdx",
				"SecTentRoleUNameIdx",
				keyUNameIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Owner",
						"Owner",
						"SecTentRoleTenant",
						"SecTentRoleTenant",
						"Tenant",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecSysGrp().readDerivedByUNameIdx( Authorization,
						Buff.getRequiredName() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecTentRoleSysRole",
						"SecTentRoleSysRole",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		Map< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole > subdictNameIdx;
		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			subdictNameIdx = dictByNameIdx.get( keyNameIdx );
		}
		else {
			subdictNameIdx = new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole >();
			dictByNameIdx.put( keyNameIdx, subdictNameIdx );
		}
		subdictNameIdx.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecTentRole.CLASS_CODE) {
				CFSecBuffSecTentRole retbuff = ((CFSecBuffSecTentRole)(schema.getCFSecBuffFactory().getFactorySecTentRole().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecTentRole readDerived( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "CFSecRamSecTentRole.readDerived";
		ICFSecSecTentRole buff;
		if( PKey == null ) {
			return( null );
		}
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentRole lockDerived( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "CFSecRamSecTentRole.lockDerived";
		ICFSecSecTentRole buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentRole[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecTentRole.readAllDerived";
		ICFSecSecTentRole[] retList = new ICFSecSecTentRole[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecTentRole > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecTentRole[] readDerivedByTenantIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamSecTentRole.readDerivedByTenantIdx";
		CFSecBuffSecTentRoleByTenantIdxKey key = (CFSecBuffSecTentRoleByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByTenantIdxKey();

		key.setRequiredTenantId( TenantId );
		ICFSecSecTentRole[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new ICFSecSecTentRole[ subdictTenantIdx.size() ];
			Iterator< CFSecBuffSecTentRole > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole > subdictTenantIdx
				= new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new ICFSecSecTentRole[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentRole[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecTentRole.readDerivedByNameIdx";
		CFSecBuffSecTentRoleByNameIdxKey key = (CFSecBuffSecTentRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByNameIdxKey();

		key.setRequiredName( Name );
		ICFSecSecTentRole[] recArray;
		if( dictByNameIdx.containsKey( key ) ) {
			Map< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole > subdictNameIdx
				= dictByNameIdx.get( key );
			recArray = new ICFSecSecTentRole[ subdictNameIdx.size() ];
			Iterator< CFSecBuffSecTentRole > iter = subdictNameIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole > subdictNameIdx
				= new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole >();
			dictByNameIdx.put( key, subdictNameIdx );
			recArray = new ICFSecSecTentRole[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentRole readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 TenantId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecTentRole.readDerivedByUNameIdx";
		CFSecBuffSecTentRoleByUNameIdxKey key = (CFSecBuffSecTentRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByUNameIdxKey();

		key.setRequiredTenantId( TenantId );
		key.setRequiredName( Name );
		ICFSecSecTentRole buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentRole readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentRoleId )
	{
		final String S_ProcName = "CFSecRamSecTentRole.readDerivedByIdIdx() ";
		ICFSecSecTentRole buff;
		if( dictByPKey.containsKey( SecTentRoleId ) ) {
			buff = dictByPKey.get( SecTentRoleId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentRole readRec( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "CFSecRamSecTentRole.readRec";
		ICFSecSecTentRole buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentRole.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentRole lockRec( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecTentRole buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentRole.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentRole[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecTentRole.readAllRec";
		ICFSecSecTentRole buff;
		ArrayList<ICFSecSecTentRole> filteredList = new ArrayList<ICFSecSecTentRole>();
		ICFSecSecTentRole[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentRole.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentRole[0] ) );
	}

	@Override
	public ICFSecSecTentRole readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentRoleId )
	{
		final String S_ProcName = "CFSecRamSecTentRole.readRecByIdIdx() ";
		ICFSecSecTentRole buff = readDerivedByIdIdx( Authorization,
			SecTentRoleId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentRole.CLASS_CODE ) ) {
			return( (ICFSecSecTentRole)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecTentRole[] readRecByTenantIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamSecTentRole.readRecByTenantIdx() ";
		ICFSecSecTentRole buff;
		ArrayList<ICFSecSecTentRole> filteredList = new ArrayList<ICFSecSecTentRole>();
		ICFSecSecTentRole[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentRole.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentRole)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentRole[0] ) );
	}

	@Override
	public ICFSecSecTentRole[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecTentRole.readRecByNameIdx() ";
		ICFSecSecTentRole buff;
		ArrayList<ICFSecSecTentRole> filteredList = new ArrayList<ICFSecSecTentRole>();
		ICFSecSecTentRole[] buffList = readDerivedByNameIdx( Authorization,
			Name );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentRole.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentRole)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentRole[0] ) );
	}

	@Override
	public ICFSecSecTentRole readRecByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 TenantId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecTentRole.readRecByUNameIdx() ";
		ICFSecSecTentRole buff = readDerivedByUNameIdx( Authorization,
			TenantId,
			Name );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentRole.CLASS_CODE ) ) {
			return( (ICFSecSecTentRole)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecTentRole updateSecTentRole( ICFSecAuthorization Authorization,
		ICFSecSecTentRole iBuff )
	{
		CFSecBuffSecTentRole Buff = (CFSecBuffSecTentRole)ensureRec(iBuff);
		$implCommaIJavaOptAtomType$ pkey = ($implCommaIJavaOptAtomType$)Buff.getPKey();
		CFSecBuffSecTentRole existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecTentRole",
				"Existing record not found",
				"Existing record not found",
				"SecTentRole",
				"SecTentRole",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecTentRole",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecTentRoleByTenantIdxKey existingKeyTenantIdx = (CFSecBuffSecTentRoleByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecBuffSecTentRoleByTenantIdxKey newKeyTenantIdx = (CFSecBuffSecTentRoleByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecBuffSecTentRoleByNameIdxKey existingKeyNameIdx = (CFSecBuffSecTentRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByNameIdxKey();
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecTentRoleByNameIdxKey newKeyNameIdx = (CFSecBuffSecTentRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByNameIdxKey();
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecTentRoleByUNameIdxKey existingKeyUNameIdx = (CFSecBuffSecTentRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByUNameIdxKey();
		existingKeyUNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecTentRoleByUNameIdxKey newKeyUNameIdx = (CFSecBuffSecTentRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByUNameIdxKey();
		newKeyUNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecTentRole",
					"SecTentRoleUNameIdx",
					"SecTentRoleUNameIdx",
					newKeyUNameIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecTentRole",
						"Owner",
						"Owner",
						"SecTentRoleTenant",
						"SecTentRoleTenant",
						"Tenant",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecSysGrp().readDerivedByUNameIdx( Authorization,
						Buff.getRequiredName() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecTentRole",
						"Container",
						"Container",
						"SecTentRoleSysRole",
						"SecTentRoleSysRole",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Update is valid

		Map< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByTenantIdx.get( existingKeyTenantIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTenantIdx.containsKey( newKeyTenantIdx ) ) {
			subdict = dictByTenantIdx.get( newKeyTenantIdx );
		}
		else {
			subdict = new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole >();
			dictByTenantIdx.put( newKeyTenantIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByNameIdx.get( existingKeyNameIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
			subdict = dictByNameIdx.get( newKeyNameIdx );
		}
		else {
			subdict = new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole >();
			dictByNameIdx.put( newKeyNameIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecTentRole( ICFSecAuthorization Authorization,
		ICFSecSecTentRole iBuff )
	{
		final String S_ProcName = "CFSecRamSecTentRoleTable.deleteSecTentRole() ";
		CFSecBuffSecTentRole Buff = (CFSecBuffSecTentRole)ensureRec(iBuff);
		int classCode;
		$implCommaIJavaOptAtomType$ pkey = ($implCommaIJavaOptAtomType$)(Buff.getPKey());
		CFSecBuffSecTentRole existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecTentRole",
				pkey );
		}
		// Short circuit self-referential code to prevent stack overflows
		Object arrCheckSecTentRoleMembByRole[] = schema.getTableSecTentRoleMemb().readDerivedByTentRoleIdx( Authorization,
						existing.getRequiredSecTentRoleId() );
		if( arrCheckSecTentRoleMembByRole.length > 0 ) {
			schema.getTableSecTentRoleMemb().deleteSecTentRoleMembByTentRoleIdx( Authorization,
						existing.getRequiredSecTentRoleId() );
		}
		CFSecBuffSecTentRoleByTenantIdxKey keyTenantIdx = (CFSecBuffSecTentRoleByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecBuffSecTentRoleByNameIdxKey keyNameIdx = (CFSecBuffSecTentRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByNameIdxKey();
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecTentRoleByUNameIdxKey keyUNameIdx = (CFSecBuffSecTentRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByUNameIdxKey();
		keyUNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< $implCommaIJavaOptAtomType$, CFSecBuffSecTentRole > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		subdict = dictByNameIdx.get( keyNameIdx );
		subdict.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	@Override
	public void deleteSecTentRoleByIdIdx( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecTentRole cur;
		LinkedList<CFSecBuffSecTentRole> matchSet = new LinkedList<CFSecBuffSecTentRole>();
		Iterator<CFSecBuffSecTentRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentRole)(schema.getTableSecTentRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentRoleId() ));
			deleteSecTentRole( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentRoleByTenantIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argTenantId )
	{
		CFSecBuffSecTentRoleByTenantIdxKey key = (CFSecBuffSecTentRoleByTenantIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteSecTentRoleByTenantIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentRoleByTenantIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleByTenantIdxKey argKey )
	{
		CFSecBuffSecTentRole cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentRole> matchSet = new LinkedList<CFSecBuffSecTentRole>();
		Iterator<CFSecBuffSecTentRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentRole)(schema.getTableSecTentRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentRoleId() ));
			deleteSecTentRole( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentRoleByNameIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		CFSecBuffSecTentRoleByNameIdxKey key = (CFSecBuffSecTentRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByNameIdxKey();
		key.setRequiredName( argName );
		deleteSecTentRoleByNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentRoleByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleByNameIdxKey argKey )
	{
		CFSecBuffSecTentRole cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentRole> matchSet = new LinkedList<CFSecBuffSecTentRole>();
		Iterator<CFSecBuffSecTentRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentRole)(schema.getTableSecTentRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentRoleId() ));
			deleteSecTentRole( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentRoleByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argTenantId,
		String argName )
	{
		CFSecBuffSecTentRoleByUNameIdxKey key = (CFSecBuffSecTentRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecTentRole().newByUNameIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredName( argName );
		deleteSecTentRoleByUNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentRoleByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentRoleByUNameIdxKey argKey )
	{
		CFSecBuffSecTentRole cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentRole> matchSet = new LinkedList<CFSecBuffSecTentRole>();
		Iterator<CFSecBuffSecTentRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentRole)(schema.getTableSecTentRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentRoleId() ));
			deleteSecTentRole( Authorization, cur );
		}
	}
}
