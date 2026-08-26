
// Description: Java 25 in-memory RAM DbIO implementation for SecClusRole.

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
 *	CFSecRamSecClusRoleTable in-memory RAM DbIO implementation
 *	for SecClusRole.
 */
public class CFSecRamSecClusRoleTable
	implements ICFSecSecClusRoleTable
{
	private ICFSecSchema schema;
	private Map< $implCommaIJavaOptAtomType$,
				CFSecBuffSecClusRole > dictByPKey
		= new HashMap< $implCommaIJavaOptAtomType$,
				CFSecBuffSecClusRole >();
	private Map< CFSecBuffSecClusRoleByClusterIdxKey,
				Map< $implCommaIJavaOptAtomType$,
					CFSecBuffSecClusRole >> dictByClusterIdx
		= new HashMap< CFSecBuffSecClusRoleByClusterIdxKey,
				Map< $implCommaIJavaOptAtomType$,
					CFSecBuffSecClusRole >>();
	private Map< CFSecBuffSecClusRoleByNameIdxKey,
				Map< $implCommaIJavaOptAtomType$,
					CFSecBuffSecClusRole >> dictByNameIdx
		= new HashMap< CFSecBuffSecClusRoleByNameIdxKey,
				Map< $implCommaIJavaOptAtomType$,
					CFSecBuffSecClusRole >>();
	private Map< CFSecBuffSecClusRoleByUNameIdxKey,
			CFSecBuffSecClusRole > dictByUNameIdx
		= new HashMap< CFSecBuffSecClusRoleByUNameIdxKey,
			CFSecBuffSecClusRole >();

	public CFSecRamSecClusRoleTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecClusRole ensureRec(ICFSecSecClusRole rec) {
		return (((CFSecBuffSecClusRoleFactoryService)(schema.getCFSecBuffFactory().getFactorySecClusRole())).ensureRec(rec));
	}

	@Override
	public ICFSecSecClusRole createSecClusRole( ICFSecAuthorization Authorization,
		ICFSecSecClusRole iBuff )
	{
		final String S_ProcName = "createSecClusRole";
		
		CFSecBuffSecClusRole Buff = (CFSecBuffSecClusRole)ensureRec(iBuff);
		$implCommaIJavaOptAtomType$ pkey;
		pkey = schema.nextSecClusRoleIdGen();
		Buff.setRequiredSecClusRoleId( pkey );
		CFSecBuffSecClusRoleByClusterIdxKey keyClusterIdx = (CFSecBuffSecClusRoleByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffSecClusRoleByNameIdxKey keyNameIdx = (CFSecBuffSecClusRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByNameIdxKey();
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecClusRoleByUNameIdxKey keyUNameIdx = (CFSecBuffSecClusRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByUNameIdxKey();
		keyUNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecClusRoleUNameIdx",
				"SecClusRoleUNameIdx",
				keyUNameIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Owner",
						"Owner",
						"SecClusRoleCluster",
						"SecClusRoleCluster",
						"Cluster",
						"Cluster",
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
						"SecClusRoleMembSysRol",
						"SecClusRoleMembSysRol",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole > subdictNameIdx;
		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			subdictNameIdx = dictByNameIdx.get( keyNameIdx );
		}
		else {
			subdictNameIdx = new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole >();
			dictByNameIdx.put( keyNameIdx, subdictNameIdx );
		}
		subdictNameIdx.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecClusRole.CLASS_CODE) {
				CFSecBuffSecClusRole retbuff = ((CFSecBuffSecClusRole)(schema.getCFSecBuffFactory().getFactorySecClusRole().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecClusRole readDerived( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "CFSecRamSecClusRole.readDerived";
		ICFSecSecClusRole buff;
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
	public ICFSecSecClusRole lockDerived( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "CFSecRamSecClusRole.lockDerived";
		ICFSecSecClusRole buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusRole[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecClusRole.readAllDerived";
		ICFSecSecClusRole[] retList = new ICFSecSecClusRole[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecClusRole > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecClusRole[] readDerivedByClusterIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 ClusterId )
	{
		final String S_ProcName = "CFSecRamSecClusRole.readDerivedByClusterIdx";
		CFSecBuffSecClusRoleByClusterIdxKey key = (CFSecBuffSecClusRoleByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByClusterIdxKey();

		key.setRequiredClusterId( ClusterId );
		ICFSecSecClusRole[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new ICFSecSecClusRole[ subdictClusterIdx.size() ];
			Iterator< CFSecBuffSecClusRole > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole > subdictClusterIdx
				= new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new ICFSecSecClusRole[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecClusRole[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecClusRole.readDerivedByNameIdx";
		CFSecBuffSecClusRoleByNameIdxKey key = (CFSecBuffSecClusRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByNameIdxKey();

		key.setRequiredName( Name );
		ICFSecSecClusRole[] recArray;
		if( dictByNameIdx.containsKey( key ) ) {
			Map< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole > subdictNameIdx
				= dictByNameIdx.get( key );
			recArray = new ICFSecSecClusRole[ subdictNameIdx.size() ];
			Iterator< CFSecBuffSecClusRole > iter = subdictNameIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole > subdictNameIdx
				= new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole >();
			dictByNameIdx.put( key, subdictNameIdx );
			recArray = new ICFSecSecClusRole[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecClusRole readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 ClusterId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecClusRole.readDerivedByUNameIdx";
		CFSecBuffSecClusRoleByUNameIdxKey key = (CFSecBuffSecClusRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByUNameIdxKey();

		key.setRequiredClusterId( ClusterId );
		key.setRequiredName( Name );
		ICFSecSecClusRole buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusRole readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecClusRoleId )
	{
		final String S_ProcName = "CFSecRamSecClusRole.readDerivedByIdIdx() ";
		ICFSecSecClusRole buff;
		if( dictByPKey.containsKey( SecClusRoleId ) ) {
			buff = dictByPKey.get( SecClusRoleId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusRole readRec( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "CFSecRamSecClusRole.readRec";
		ICFSecSecClusRole buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecClusRole.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusRole lockRec( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecClusRole buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecClusRole.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusRole[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecClusRole.readAllRec";
		ICFSecSecClusRole buff;
		ArrayList<ICFSecSecClusRole> filteredList = new ArrayList<ICFSecSecClusRole>();
		ICFSecSecClusRole[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusRole.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusRole[0] ) );
	}

	@Override
	public ICFSecSecClusRole readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecClusRoleId )
	{
		final String S_ProcName = "CFSecRamSecClusRole.readRecByIdIdx() ";
		ICFSecSecClusRole buff = readDerivedByIdIdx( Authorization,
			SecClusRoleId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusRole.CLASS_CODE ) ) {
			return( (ICFSecSecClusRole)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecClusRole[] readRecByClusterIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 ClusterId )
	{
		final String S_ProcName = "CFSecRamSecClusRole.readRecByClusterIdx() ";
		ICFSecSecClusRole buff;
		ArrayList<ICFSecSecClusRole> filteredList = new ArrayList<ICFSecSecClusRole>();
		ICFSecSecClusRole[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusRole.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecClusRole)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusRole[0] ) );
	}

	@Override
	public ICFSecSecClusRole[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecClusRole.readRecByNameIdx() ";
		ICFSecSecClusRole buff;
		ArrayList<ICFSecSecClusRole> filteredList = new ArrayList<ICFSecSecClusRole>();
		ICFSecSecClusRole[] buffList = readDerivedByNameIdx( Authorization,
			Name );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusRole.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecClusRole)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusRole[0] ) );
	}

	@Override
	public ICFSecSecClusRole readRecByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 ClusterId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecClusRole.readRecByUNameIdx() ";
		ICFSecSecClusRole buff = readDerivedByUNameIdx( Authorization,
			ClusterId,
			Name );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusRole.CLASS_CODE ) ) {
			return( (ICFSecSecClusRole)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecClusRole updateSecClusRole( ICFSecAuthorization Authorization,
		ICFSecSecClusRole iBuff )
	{
		CFSecBuffSecClusRole Buff = (CFSecBuffSecClusRole)ensureRec(iBuff);
		$implCommaIJavaOptAtomType$ pkey = ($implCommaIJavaOptAtomType$)Buff.getPKey();
		CFSecBuffSecClusRole existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecClusRole",
				"Existing record not found",
				"Existing record not found",
				"SecClusRole",
				"SecClusRole",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecClusRole",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecClusRoleByClusterIdxKey existingKeyClusterIdx = (CFSecBuffSecClusRoleByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffSecClusRoleByClusterIdxKey newKeyClusterIdx = (CFSecBuffSecClusRoleByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffSecClusRoleByNameIdxKey existingKeyNameIdx = (CFSecBuffSecClusRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByNameIdxKey();
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecClusRoleByNameIdxKey newKeyNameIdx = (CFSecBuffSecClusRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByNameIdxKey();
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecClusRoleByUNameIdxKey existingKeyUNameIdx = (CFSecBuffSecClusRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByUNameIdxKey();
		existingKeyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecClusRoleByUNameIdxKey newKeyUNameIdx = (CFSecBuffSecClusRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByUNameIdxKey();
		newKeyUNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecClusRole",
					"SecClusRoleUNameIdx",
					"SecClusRoleUNameIdx",
					newKeyUNameIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecClusRole",
						"Owner",
						"Owner",
						"SecClusRoleCluster",
						"SecClusRoleCluster",
						"Cluster",
						"Cluster",
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
						"updateSecClusRole",
						"Container",
						"Container",
						"SecClusRoleMembSysRol",
						"SecClusRoleMembSysRol",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Update is valid

		Map< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByClusterIdx.get( existingKeyClusterIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusterIdx.containsKey( newKeyClusterIdx ) ) {
			subdict = dictByClusterIdx.get( newKeyClusterIdx );
		}
		else {
			subdict = new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
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
			subdict = new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole >();
			dictByNameIdx.put( newKeyNameIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecClusRole( ICFSecAuthorization Authorization,
		ICFSecSecClusRole iBuff )
	{
		final String S_ProcName = "CFSecRamSecClusRoleTable.deleteSecClusRole() ";
		CFSecBuffSecClusRole Buff = (CFSecBuffSecClusRole)ensureRec(iBuff);
		int classCode;
		$implCommaIJavaOptAtomType$ pkey = ($implCommaIJavaOptAtomType$)(Buff.getPKey());
		CFSecBuffSecClusRole existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecClusRole",
				pkey );
		}
		// Short circuit self-referential code to prevent stack overflows
		Object arrCheckSecClusRoleMembByGrp[] = schema.getTableSecClusRoleMemb().readDerivedByClusRoleIdx( Authorization,
						existing.getRequiredSecClusRoleId() );
		if( arrCheckSecClusRoleMembByGrp.length > 0 ) {
			schema.getTableSecClusRoleMemb().deleteSecClusRoleMembByClusRoleIdx( Authorization,
						existing.getRequiredSecClusRoleId() );
		}
		CFSecBuffSecClusRoleByClusterIdxKey keyClusterIdx = (CFSecBuffSecClusRoleByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffSecClusRoleByNameIdxKey keyNameIdx = (CFSecBuffSecClusRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByNameIdxKey();
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecClusRoleByUNameIdxKey keyUNameIdx = (CFSecBuffSecClusRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByUNameIdxKey();
		keyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< $implCommaIJavaOptAtomType$, CFSecBuffSecClusRole > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByNameIdx.get( keyNameIdx );
		subdict.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	@Override
	public void deleteSecClusRoleByIdIdx( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecClusRole cur;
		LinkedList<CFSecBuffSecClusRole> matchSet = new LinkedList<CFSecBuffSecClusRole>();
		Iterator<CFSecBuffSecClusRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusRole)(schema.getTableSecClusRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusRoleId() ));
			deleteSecClusRole( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusRoleByClusterIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argClusterId )
	{
		CFSecBuffSecClusRoleByClusterIdxKey key = (CFSecBuffSecClusRoleByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecClusRoleByClusterIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusRoleByClusterIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleByClusterIdxKey argKey )
	{
		CFSecBuffSecClusRole cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusRole> matchSet = new LinkedList<CFSecBuffSecClusRole>();
		Iterator<CFSecBuffSecClusRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusRole)(schema.getTableSecClusRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusRoleId() ));
			deleteSecClusRole( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusRoleByNameIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		CFSecBuffSecClusRoleByNameIdxKey key = (CFSecBuffSecClusRoleByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByNameIdxKey();
		key.setRequiredName( argName );
		deleteSecClusRoleByNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusRoleByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleByNameIdxKey argKey )
	{
		CFSecBuffSecClusRole cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusRole> matchSet = new LinkedList<CFSecBuffSecClusRole>();
		Iterator<CFSecBuffSecClusRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusRole)(schema.getTableSecClusRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusRoleId() ));
			deleteSecClusRole( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusRoleByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argClusterId,
		String argName )
	{
		CFSecBuffSecClusRoleByUNameIdxKey key = (CFSecBuffSecClusRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusRole().newByUNameIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredName( argName );
		deleteSecClusRoleByUNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusRoleByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleByUNameIdxKey argKey )
	{
		CFSecBuffSecClusRole cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusRole> matchSet = new LinkedList<CFSecBuffSecClusRole>();
		Iterator<CFSecBuffSecClusRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusRole)(schema.getTableSecClusRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusRoleId() ));
			deleteSecClusRole( Authorization, cur );
		}
	}
}
