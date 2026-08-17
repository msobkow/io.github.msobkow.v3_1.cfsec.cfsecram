
// Description: Java 25 in-memory RAM DbIO implementation for SecClusGrp.

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
 *	CFSecRamSecClusGrpTable in-memory RAM DbIO implementation
 *	for SecClusGrp.
 */
public class CFSecRamSecClusGrpTable
	implements ICFSecSecClusGrpTable
{
	private ICFSecSchema schema;
	private Map< ICFLibKeyHash256,
				CFSecBuffSecClusGrp > dictByPKey
		= new HashMap< ICFLibKeyHash256,
				CFSecBuffSecClusGrp >();
	private Map< CFSecBuffSecClusGrpByClusterIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecClusGrp >> dictByClusterIdx
		= new HashMap< CFSecBuffSecClusGrpByClusterIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecClusGrp >>();
	private Map< CFSecBuffSecClusGrpByNameIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecClusGrp >> dictByNameIdx
		= new HashMap< CFSecBuffSecClusGrpByNameIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecClusGrp >>();
	private Map< CFSecBuffSecClusGrpByUNameIdxKey,
			CFSecBuffSecClusGrp > dictByUNameIdx
		= new HashMap< CFSecBuffSecClusGrpByUNameIdxKey,
			CFSecBuffSecClusGrp >();

	public CFSecRamSecClusGrpTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecClusGrp ensureRec(ICFSecSecClusGrp rec) {
		return (((CFSecBuffSecClusGrpFactoryService)(schema.getCFSecBuffFactory().getFactorySecClusGrp())).ensureRec(rec));
	}

	@Override
	public ICFSecSecClusGrp createSecClusGrp( ICFSecAuthorization Authorization,
		ICFSecSecClusGrp iBuff )
	{
		final String S_ProcName = "createSecClusGrp";
		
		CFSecBuffSecClusGrp Buff = (CFSecBuffSecClusGrp)ensureRec(iBuff);
		ICFLibKeyHash256 pkey;
		pkey = schema.nextSecClusGrpIdGen();
		Buff.setRequiredSecClusGrpId( pkey );
		CFSecBuffSecClusGrpByClusterIdxKey keyClusterIdx = (CFSecBuffSecClusGrpByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffSecClusGrpByNameIdxKey keyNameIdx = (CFSecBuffSecClusGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByNameIdxKey();
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecClusGrpByUNameIdxKey keyUNameIdx = (CFSecBuffSecClusGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByUNameIdxKey();
		keyUNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecClusGrpUNameIdx",
				"SecClusGrpUNameIdx",
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
						"SecClusGrpCluster",
						"SecClusGrpCluster",
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
						"SecClusGrpRefSysGrp",
						"SecClusGrpRefSysGrp",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< ICFLibKeyHash256, CFSecBuffSecClusGrp > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< ICFLibKeyHash256, CFSecBuffSecClusGrp >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< ICFLibKeyHash256, CFSecBuffSecClusGrp > subdictNameIdx;
		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			subdictNameIdx = dictByNameIdx.get( keyNameIdx );
		}
		else {
			subdictNameIdx = new HashMap< ICFLibKeyHash256, CFSecBuffSecClusGrp >();
			dictByNameIdx.put( keyNameIdx, subdictNameIdx );
		}
		subdictNameIdx.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecClusGrp.CLASS_CODE) {
				CFSecBuffSecClusGrp retbuff = ((CFSecBuffSecClusGrp)(schema.getCFSecBuffFactory().getFactorySecClusGrp().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecClusGrp readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.readDerived";
		ICFSecSecClusGrp buff;
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
	public ICFSecSecClusGrp lockDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.lockDerived";
		ICFSecSecClusGrp buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrp[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecClusGrp.readAllDerived";
		ICFSecSecClusGrp[] retList = new ICFSecSecClusGrp[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecClusGrp > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecClusGrp[] readDerivedByClusterIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 ClusterId )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.readDerivedByClusterIdx";
		CFSecBuffSecClusGrpByClusterIdxKey key = (CFSecBuffSecClusGrpByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByClusterIdxKey();

		key.setRequiredClusterId( ClusterId );
		ICFSecSecClusGrp[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< ICFLibKeyHash256, CFSecBuffSecClusGrp > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new ICFSecSecClusGrp[ subdictClusterIdx.size() ];
			Iterator< CFSecBuffSecClusGrp > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< ICFLibKeyHash256, CFSecBuffSecClusGrp > subdictClusterIdx
				= new HashMap< ICFLibKeyHash256, CFSecBuffSecClusGrp >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new ICFSecSecClusGrp[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecClusGrp[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.readDerivedByNameIdx";
		CFSecBuffSecClusGrpByNameIdxKey key = (CFSecBuffSecClusGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByNameIdxKey();

		key.setRequiredName( Name );
		ICFSecSecClusGrp[] recArray;
		if( dictByNameIdx.containsKey( key ) ) {
			Map< ICFLibKeyHash256, CFSecBuffSecClusGrp > subdictNameIdx
				= dictByNameIdx.get( key );
			recArray = new ICFSecSecClusGrp[ subdictNameIdx.size() ];
			Iterator< CFSecBuffSecClusGrp > iter = subdictNameIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< ICFLibKeyHash256, CFSecBuffSecClusGrp > subdictNameIdx
				= new HashMap< ICFLibKeyHash256, CFSecBuffSecClusGrp >();
			dictByNameIdx.put( key, subdictNameIdx );
			recArray = new ICFSecSecClusGrp[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecClusGrp readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 ClusterId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.readDerivedByUNameIdx";
		CFSecBuffSecClusGrpByUNameIdxKey key = (CFSecBuffSecClusGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByUNameIdxKey();

		key.setRequiredClusterId( ClusterId );
		key.setRequiredName( Name );
		ICFSecSecClusGrp buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrp readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecClusGrpId )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.readDerivedByIdIdx() ";
		ICFSecSecClusGrp buff;
		if( dictByPKey.containsKey( SecClusGrpId ) ) {
			buff = dictByPKey.get( SecClusGrpId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrp readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.readRec";
		ICFSecSecClusGrp buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecClusGrp.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrp lockRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecClusGrp buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecClusGrp.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrp[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.readAllRec";
		ICFSecSecClusGrp buff;
		ArrayList<ICFSecSecClusGrp> filteredList = new ArrayList<ICFSecSecClusGrp>();
		ICFSecSecClusGrp[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrp.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusGrp[0] ) );
	}

	@Override
	public ICFSecSecClusGrp readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecClusGrpId )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.readRecByIdIdx() ";
		ICFSecSecClusGrp buff = readDerivedByIdIdx( Authorization,
			SecClusGrpId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrp.CLASS_CODE ) ) {
			return( (ICFSecSecClusGrp)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecClusGrp[] readRecByClusterIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 ClusterId )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.readRecByClusterIdx() ";
		ICFSecSecClusGrp buff;
		ArrayList<ICFSecSecClusGrp> filteredList = new ArrayList<ICFSecSecClusGrp>();
		ICFSecSecClusGrp[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrp.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecClusGrp)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusGrp[0] ) );
	}

	@Override
	public ICFSecSecClusGrp[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.readRecByNameIdx() ";
		ICFSecSecClusGrp buff;
		ArrayList<ICFSecSecClusGrp> filteredList = new ArrayList<ICFSecSecClusGrp>();
		ICFSecSecClusGrp[] buffList = readDerivedByNameIdx( Authorization,
			Name );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrp.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecClusGrp)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusGrp[0] ) );
	}

	@Override
	public ICFSecSecClusGrp readRecByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 ClusterId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecClusGrp.readRecByUNameIdx() ";
		ICFSecSecClusGrp buff = readDerivedByUNameIdx( Authorization,
			ClusterId,
			Name );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrp.CLASS_CODE ) ) {
			return( (ICFSecSecClusGrp)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecClusGrp updateSecClusGrp( ICFSecAuthorization Authorization,
		ICFSecSecClusGrp iBuff )
	{
		CFSecBuffSecClusGrp Buff = (CFSecBuffSecClusGrp)ensureRec(iBuff);
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)Buff.getPKey();
		CFSecBuffSecClusGrp existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecClusGrp",
				"Existing record not found",
				"Existing record not found",
				"SecClusGrp",
				"SecClusGrp",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecClusGrp",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecClusGrpByClusterIdxKey existingKeyClusterIdx = (CFSecBuffSecClusGrpByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffSecClusGrpByClusterIdxKey newKeyClusterIdx = (CFSecBuffSecClusGrpByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffSecClusGrpByNameIdxKey existingKeyNameIdx = (CFSecBuffSecClusGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByNameIdxKey();
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecClusGrpByNameIdxKey newKeyNameIdx = (CFSecBuffSecClusGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByNameIdxKey();
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecClusGrpByUNameIdxKey existingKeyUNameIdx = (CFSecBuffSecClusGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByUNameIdxKey();
		existingKeyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecClusGrpByUNameIdxKey newKeyUNameIdx = (CFSecBuffSecClusGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByUNameIdxKey();
		newKeyUNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecClusGrp",
					"SecClusGrpUNameIdx",
					"SecClusGrpUNameIdx",
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
						"updateSecClusGrp",
						"Owner",
						"Owner",
						"SecClusGrpCluster",
						"SecClusGrpCluster",
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
						"updateSecClusGrp",
						"Container",
						"Container",
						"SecClusGrpRefSysGrp",
						"SecClusGrpRefSysGrp",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Update is valid

		Map< ICFLibKeyHash256, CFSecBuffSecClusGrp > subdict;

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
			subdict = new HashMap< ICFLibKeyHash256, CFSecBuffSecClusGrp >();
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
			subdict = new HashMap< ICFLibKeyHash256, CFSecBuffSecClusGrp >();
			dictByNameIdx.put( newKeyNameIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecClusGrp( ICFSecAuthorization Authorization,
		ICFSecSecClusGrp iBuff )
	{
		final String S_ProcName = "CFSecRamSecClusGrpTable.deleteSecClusGrp() ";
		CFSecBuffSecClusGrp Buff = (CFSecBuffSecClusGrp)ensureRec(iBuff);
		int classCode;
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)(Buff.getPKey());
		CFSecBuffSecClusGrp existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecClusGrp",
				pkey );
		}
					schema.getTableSecClusGrpMemb().deleteSecClusGrpMembByClusGrpIdx( Authorization,
						existing.getRequiredSecClusGrpId() );
		CFSecBuffSecClusGrpByClusterIdxKey keyClusterIdx = (CFSecBuffSecClusGrpByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffSecClusGrpByNameIdxKey keyNameIdx = (CFSecBuffSecClusGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByNameIdxKey();
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecClusGrpByUNameIdxKey keyUNameIdx = (CFSecBuffSecClusGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByUNameIdxKey();
		keyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< ICFLibKeyHash256, CFSecBuffSecClusGrp > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByNameIdx.get( keyNameIdx );
		subdict.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	@Override
	public void deleteSecClusGrpByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecClusGrp cur;
		LinkedList<CFSecBuffSecClusGrp> matchSet = new LinkedList<CFSecBuffSecClusGrp>();
		Iterator<CFSecBuffSecClusGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusGrp)(schema.getTableSecClusGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusGrpId() ));
			deleteSecClusGrp( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusGrpByClusterIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argClusterId )
	{
		CFSecBuffSecClusGrpByClusterIdxKey key = (CFSecBuffSecClusGrpByClusterIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecClusGrpByClusterIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusGrpByClusterIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpByClusterIdxKey argKey )
	{
		CFSecBuffSecClusGrp cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusGrp> matchSet = new LinkedList<CFSecBuffSecClusGrp>();
		Iterator<CFSecBuffSecClusGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusGrp)(schema.getTableSecClusGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusGrpId() ));
			deleteSecClusGrp( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusGrpByNameIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		CFSecBuffSecClusGrpByNameIdxKey key = (CFSecBuffSecClusGrpByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByNameIdxKey();
		key.setRequiredName( argName );
		deleteSecClusGrpByNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusGrpByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpByNameIdxKey argKey )
	{
		CFSecBuffSecClusGrp cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusGrp> matchSet = new LinkedList<CFSecBuffSecClusGrp>();
		Iterator<CFSecBuffSecClusGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusGrp)(schema.getTableSecClusGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusGrpId() ));
			deleteSecClusGrp( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusGrpByUNameIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argClusterId,
		String argName )
	{
		CFSecBuffSecClusGrpByUNameIdxKey key = (CFSecBuffSecClusGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecClusGrp().newByUNameIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredName( argName );
		deleteSecClusGrpByUNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusGrpByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpByUNameIdxKey argKey )
	{
		CFSecBuffSecClusGrp cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusGrp> matchSet = new LinkedList<CFSecBuffSecClusGrp>();
		Iterator<CFSecBuffSecClusGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusGrp)(schema.getTableSecClusGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusGrpId() ));
			deleteSecClusGrp( Authorization, cur );
		}
	}
}
